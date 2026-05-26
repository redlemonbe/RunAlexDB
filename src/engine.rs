//! In-memory SQL engine — tables, rows, query dispatch.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use sqlparser::ast::{
    ColumnDef, Expr, ObjectName, Query, SetExpr, Statement, Values,
};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;

use crate::config::Config;

// ── Types ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum Value {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }
    pub fn to_display(&self) -> Option<String> {
        match self {
            Value::Null => None,
            Value::Int(i) => Some(i.to_string()),
            Value::Float(f) => Some(f.to_string()),
            Value::Text(s) => Some(s.clone()),
            Value::Bytes(b) => Some(hex::encode(b)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub primary_key: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ColumnType {
    Int,
    BigInt,
    Float,
    VarChar(u16),
    Text,
    Blob,
    Timestamp,
}

impl ColumnType {
    pub fn mysql_type_byte(&self) -> u8 {
        match self {
            ColumnType::Int | ColumnType::BigInt => 0x08,
            ColumnType::Float => 0x05,
            ColumnType::VarChar(_) | ColumnType::Text => 0xfd,
            ColumnType::Blob => 0xfc,
            ColumnType::Timestamp => 0x07,
        }
    }
}

pub type Row = Vec<Value>;

#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    pub schema: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    pub next_auto: i64,
}

#[derive(Debug)]
pub struct Database {
    pub name: String,
    pub tables: HashMap<String, Table>,
}

// ── Engine ─────────────────────────────────────────────────────────────────

pub struct Engine {
    pub databases: RwLock<HashMap<String, Arc<RwLock<Database>>>>,
}

impl Engine {
    pub fn new(_cfg: &Config) -> Self {
        let mut dbs = HashMap::new();
        // Built-in schemas
        for name in &["information_schema", "performance_schema", "mysql", "sys"] {
            dbs.insert(name.to_string(), Arc::new(RwLock::new(Database {
                name: name.to_string(),
                tables: HashMap::new(),
            })));
        }
        Self { databases: RwLock::new(dbs) }
    }

    /// Execute a SQL statement string in the context of `current_db`.
    pub fn execute(&self, sql: &str, current_db: &Option<String>) -> QueryResult {
        // Handle built-in special queries first
        let sql_upper = sql.trim().to_uppercase();
        if sql_upper == "SELECT 1" || sql_upper == "SELECT 1;" {
            return QueryResult::rows(vec!["1"], vec![vec![Some(String::from("1"))]]);
        }
        if sql_upper.starts_with("SELECT VERSION") {
            return QueryResult::rows(
                vec!["VERSION()"],
                vec![vec![Some(String::from("8.0.32-RunAlexDB"))]],
            );
        }
        if sql_upper.starts_with("SHOW DATABASES") {
            let dbs = self.databases.read().unwrap();
            let rows: Vec<_> = dbs.keys()
                .filter(|n| !n.starts_with("information_schema") && !n.starts_with("performance_schema") && n.as_str() != "mysql" && n.as_str() != "sys")
                .map(|n| vec![Some(n.clone())])
                .collect();
            return QueryResult::rows(vec!["Database"], rows);
        }
        if sql_upper.starts_with("SHOW TABLES") {
            let db_name = current_db.as_deref().unwrap_or("test");
            if let Some(db_arc) = self.databases.read().unwrap().get(db_name) {
                let db = db_arc.read().unwrap();
                let rows: Vec<_> = db.tables.keys()
                    .map(|n| vec![Some(n.clone())])
                    .collect();
                return QueryResult::rows(vec!["Tables"], rows);
            }
            return QueryResult::ok(0, 0);
        }

        // Parse with sqlparser
        let dialect = MySqlDialect {};
        let stmts = match Parser::parse_sql(&dialect, sql) {
            Ok(s) => s,
            Err(e) => return QueryResult::err(1064, &format!("Parse error: {e}")),
        };

        let mut last = QueryResult::ok(0, 0);
        for stmt in stmts {
            last = self.exec_stmt(stmt, current_db);
        }
        last
    }

    fn exec_stmt(&self, stmt: Statement, current_db: &Option<String>) -> QueryResult {
        match stmt {
            Statement::CreateDatabase { db_name, .. } => {
                self.create_database(&db_name.to_string())
            }
            Statement::CreateTable(create) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.create_table(db_name, create.name, create.columns)
            }
            Statement::Insert(insert) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.insert(db_name, &insert.table.to_string(), insert.source)
            }
            Statement::Query(q) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.select(db_name, *q)
            }
            Statement::Drop { object_type, names, .. } => {
                let _ = (object_type, names); // TODO
                QueryResult::ok(0, 0)
            }
            Statement::Use(u) => {
                // USE db just returns OK — the session tracks current_db
                let _ = u;
                QueryResult::ok(0, 0)
            }
            _ => QueryResult::err(1295, "Statement not yet supported"),
        }
    }

    fn create_database(&self, name: &str) -> QueryResult {
        let mut dbs = self.databases.write().unwrap();
        dbs.entry(name.to_string()).or_insert_with(|| {
            Arc::new(RwLock::new(Database { name: name.to_string(), tables: HashMap::new() }))
        });
        QueryResult::ok(1, 0)
    }

    fn create_table(
        &self,
        db_name: &str,
        name: ObjectName,
        col_defs: Vec<ColumnDef>,
    ) -> QueryResult {
        let table_name = name.0.last()
            .map(|p| p.as_ident().map(|i| i.value.clone()).unwrap_or_default())
            .unwrap_or_default();

        let columns: Vec<Column> = col_defs.iter().map(|c| {
            let col_type = sql_type_to_col_type(&c.data_type);
            Column {
                name: c.name.value.clone(),
                col_type,
                nullable: true,
                primary_key: false,
            }
        }).collect();

        let dbs = self.databases.read().unwrap();
        if let Some(db_arc) = dbs.get(db_name) {
            let mut db = db_arc.write().unwrap();
            db.tables.insert(table_name.clone(), Table {
                name: table_name,
                schema: db_name.to_string(),
                columns,
                rows: vec![],
                next_auto: 1,
            });
            QueryResult::ok(0, 0)
        } else {
            QueryResult::err(1049, &format!("Unknown database '{db_name}'"))
        }
    }

    fn insert(
        &self,
        db_name: &str,
        table_name: &str,
        source: Option<Box<Query>>,
    ) -> QueryResult {
        let Some(source) = source else {
            return QueryResult::err(1064, "INSERT without VALUES");
        };
        let SetExpr::Values(Values { rows, .. }) = *source.body else {
            return QueryResult::err(1064, "Only VALUES inserts supported");
        };

        let dbs = self.databases.read().unwrap();
        let Some(db_arc) = dbs.get(db_name) else {
            return QueryResult::err(1049, &format!("Unknown database '{db_name}'"));
        };
        let mut db = db_arc.write().unwrap();
        let Some(table) = db.tables.get_mut(table_name) else {
            return QueryResult::err(1146, &format!("Table '{db_name}.{table_name}' doesn't exist"));
        };

        let count = rows.len() as u64;
        for row_exprs in rows {
            let row: Row = row_exprs.into_iter().map(expr_to_value).collect();
            table.rows.push(row);
        }
        QueryResult::ok(count, 0)
    }

    fn select(&self, db_name: &str, query: Query) -> QueryResult {
        // Very basic SELECT — only handles SELECT * FROM table and SELECT expr
        let SetExpr::Select(sel) = *query.body else {
            return QueryResult::err(1295, "Complex SELECT not yet supported");
        };

        if sel.from.is_empty() {
            // SELECT without FROM — evaluate projection
            let cols: Vec<String> = sel.projection.iter().map(|p| p.to_string()).collect();
            let vals: Vec<Option<String>> = sel.projection.iter().map(|p| {
                match p {
                    sqlparser::ast::SelectItem::UnnamedExpr(Expr::Value(ref vs)) => {
                        Some(vs.value.to_string().trim_matches('\'').to_owned())
                    }
                    sqlparser::ast::SelectItem::UnnamedExpr(Expr::Function(f)) => {
                        Some(f.to_string())
                    }
                    _ => Some(p.to_string()),
                }
            }).collect();
            return QueryResult::rows(cols, vec![vals]);
        }

        let table_name = sel.from[0].relation.to_string();
        let dbs = self.databases.read().unwrap();
        let Some(db_arc) = dbs.get(db_name) else {
            return QueryResult::err(1049, &format!("Unknown database '{db_name}'"));
        };
        let db = db_arc.read().unwrap();
        let Some(table) = db.tables.get(&table_name) else {
            return QueryResult::err(1146, &format!("Table '{db_name}.{table_name}' doesn't exist"));
        };

        let col_names: Vec<String> = table.columns.iter().map(|c| c.name.clone()).collect();
        let result_rows: Vec<Vec<Option<String>>> = table.rows.iter().map(|row| {
            row.iter().map(|v| v.to_display()).collect()
        }).collect();

        QueryResult::rows(col_names, result_rows)
    }
}

// ── QueryResult ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum QueryResult {
    Ok { affected: u64, last_insert_id: u64 },
    Err { code: u16, message: String },
    Rows { columns: Vec<String>, rows: Vec<Vec<Option<String>>> },
}

impl QueryResult {
    pub fn ok(affected: u64, last_insert_id: u64) -> Self {
        Self::Ok { affected, last_insert_id }
    }
    pub fn err(code: u16, msg: &str) -> Self {
        Self::Err { code, message: msg.to_owned() }
    }
    pub fn rows(cols: Vec<impl Into<String>>, rows: Vec<Vec<Option<impl Into<String>>>>) -> Self {
        Self::Rows {
            columns: cols.into_iter().map(|c| c.into()).collect(),
            rows: rows.into_iter().map(|r| r.into_iter().map(|v| v.map(|s| s.into())).collect()).collect(),
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn sql_type_to_col_type(dt: &sqlparser::ast::DataType) -> ColumnType {
    use sqlparser::ast::DataType::*;
    match dt {
        Int(_) | Integer(_) | SmallInt(_) | TinyInt(_) => ColumnType::Int,
        BigInt(_) => ColumnType::BigInt,
        Float(_) | Real | Double(_) | DoublePrecision => ColumnType::Float,
        Varchar(Some(n)) => {
            use sqlparser::ast::CharacterLength;
            match n {
                CharacterLength::IntegerLength { length, .. } => ColumnType::VarChar(*length as u16),
                _ => ColumnType::VarChar(255),
            }
        },
        Varchar(_) | Text | MediumText | LongText => ColumnType::Text,
        Blob(_) | Binary(_) | Varbinary(_) => ColumnType::Blob,
        Timestamp(_, _) | Datetime(_) => ColumnType::Timestamp,
        _ => ColumnType::Text,
    }
}

fn expr_to_value(expr: Expr) -> Value {
    match expr {
        Expr::Value(vs) => match vs.value {
            sqlparser::ast::Value::Number(n, _) => {
                if let Ok(i) = n.parse::<i64>() {
                    Value::Int(i)
                } else if let Ok(f) = n.parse::<f64>() {
                    Value::Float(f)
                } else {
                    Value::Text(n)
                }
            }
            sqlparser::ast::Value::SingleQuotedString(s) => Value::Text(s),
            sqlparser::ast::Value::Null => Value::Null,
            other => Value::Text(other.to_string()),
        },
        other => Value::Text(other.to_string()),
    }
}

fn _check_result(_: Result<()>) {}

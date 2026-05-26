//! In-memory SQL engine — tables, rows, query dispatch.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use anyhow::{bail, Result};
use sqlparser::ast::{
    Assignment, BinaryOperator, ColumnDef, Expr, ObjectName,
    Query, SelectItem, SetExpr, Statement, UnaryOperator, Values,
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
    pub fn new(cfg: &Config) -> Self {
        let mut dbs = HashMap::new();
        // Built-in schemas
        for name in &["information_schema", "performance_schema", "mysql", "sys", "test"] {
            dbs.insert(name.to_string(), Arc::new(RwLock::new(Database {
                name: name.to_string(),
                tables: HashMap::new(),
            })));
        }
        let engine = Self { databases: RwLock::new(dbs) };

        // Auto-load persisted data on startup
        let persist_path = format!("{}/runalexdb.sql", cfg.data_dir);
        if let Ok(sql) = std::fs::read_to_string(&persist_path) {
            tracing::info!("Loading persisted data from {persist_path}");
            engine.restore_sql(&sql);
        }

        engine
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
            let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
            let rows: Vec<_> = dbs.keys()
                .filter(|n| !n.starts_with("information_schema") && !n.starts_with("performance_schema") && n.as_str() != "mysql" && n.as_str() != "sys")
                .map(|n| vec![Some(n.clone())])
                .collect();
            return QueryResult::rows(vec!["Database"], rows);
        }
        if sql_upper.starts_with("SHOW TABLES") {
            let db_name = current_db.as_deref().unwrap_or("test");
            if let Some(db_arc) = self.databases.read().unwrap_or_else(|e| e.into_inner()).get(db_name) {
                let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
                let rows: Vec<_> = db.tables.keys()
                    .map(|n| vec![Some(n.clone())])
                    .collect();
                return QueryResult::rows(vec!["Tables"], rows);
            }
            return QueryResult::ok(0, 0);
        }

        // SET statements (ignored — just return OK)
        if sql_upper.starts_with("SET ") || sql_upper == "BEGIN" || sql_upper == "COMMIT"
            || sql_upper == "ROLLBACK" || sql_upper == "ROLLBACK;" || sql_upper == "COMMIT;" {
            return QueryResult::ok(0, 0);
        }

        // INFORMATION_SCHEMA.TABLES
        if sql_upper.contains("INFORMATION_SCHEMA.TABLES") || sql_upper.contains("INFORMATION_SCHEMA.`TABLES`") {
            let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
            let cols = vec!["TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE", "ENGINE", "TABLE_ROWS"];
            let mut rows: Vec<Vec<Option<String>>> = Vec::new();
            for (db_name, db_arc) in dbs.iter() {
                if db_name.starts_with("information_schema") || db_name.starts_with("performance_schema") {
                    continue;
                }
                let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
                for (tname, table) in &db.tables {
                    rows.push(vec![
                        Some("def".into()),
                        Some(db_name.clone()),
                        Some(tname.clone()),
                        Some("BASE TABLE".into()),
                        Some("RunAlexDB".into()),
                        Some(table.rows.len().to_string()),
                    ]);
                }
            }
            return QueryResult::rows(cols, rows);
        }

        // INFORMATION_SCHEMA.COLUMNS
        if sql_upper.contains("INFORMATION_SCHEMA.COLUMNS") || sql_upper.contains("INFORMATION_SCHEMA.`COLUMNS`") {
            let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
            let cols = vec!["TABLE_CATALOG", "TABLE_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "ORDINAL_POSITION", "COLUMN_TYPE", "IS_NULLABLE", "COLUMN_KEY"];
            let mut rows: Vec<Vec<Option<String>>> = Vec::new();
            for (db_name, db_arc) in dbs.iter() {
                if db_name.starts_with("information_schema") || db_name.starts_with("performance_schema") {
                    continue;
                }
                let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
                for (tname, table) in &db.tables {
                    for (pos, col) in table.columns.iter().enumerate() {
                        let col_type_str = match &col.col_type {
                            crate::engine::ColumnType::Int => "int".to_string(),
                            crate::engine::ColumnType::BigInt => "bigint".to_string(),
                            crate::engine::ColumnType::Float => "double".to_string(),
                            crate::engine::ColumnType::VarChar(n) => format!("varchar({})", n),
                            crate::engine::ColumnType::Text => "text".to_string(),
                            crate::engine::ColumnType::Blob => "blob".to_string(),
                            crate::engine::ColumnType::Timestamp => "timestamp".to_string(),
                        };
                        rows.push(vec![
                            Some("def".into()),
                            Some(db_name.clone()),
                            Some(tname.clone()),
                            Some(col.name.clone()),
                            Some((pos + 1).to_string()),
                            Some(col_type_str),
                            Some(if col.nullable { "YES" } else { "NO" }.into()),
                            Some(if col.primary_key { "PRI" } else { "" }.into()),
                        ]);
                    }
                }
            }
            return QueryResult::rows(cols, rows);
        }

        // INFORMATION_SCHEMA.SCHEMATA
        if sql_upper.contains("INFORMATION_SCHEMA.SCHEMATA") {
            let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
            let cols = vec!["CATALOG_NAME", "SCHEMA_NAME", "DEFAULT_CHARACTER_SET_NAME", "DEFAULT_COLLATION_NAME"];
            let rows: Vec<Vec<Option<String>>> = dbs.keys()
                .filter(|n| !n.starts_with("information_schema") && !n.starts_with("performance_schema") && n.as_str() != "mysql" && n.as_str() != "sys")
                .map(|n| vec![
                    Some("def".into()),
                    Some(n.clone()),
                    Some("utf8mb4".to_owned()),
                    Some("utf8mb4_0900_ai_ci".to_owned()),
                ])
                .collect();
            return QueryResult::rows(cols, rows);
        }

        // SHOW VARIABLES (clients check these)
        if sql_upper.starts_with("SHOW VARIABLES") || sql_upper.starts_with("SHOW SESSION VARIABLES") {
            return QueryResult::rows(
                vec!["Variable_name", "Value"],
                vec![
                    vec![Some("character_set_client".to_owned()), Some("utf8mb4".to_owned())],
                    vec![Some("character_set_connection".to_owned()), Some("utf8mb4".to_owned())],
                    vec![Some("character_set_results".to_owned()), Some("utf8mb4".to_owned())],
                    vec![Some("collation_connection".to_owned()), Some("utf8mb4_0900_ai_ci".to_owned())],
                    vec![Some("max_allowed_packet".to_owned()), Some("67108864".to_owned())],
                    vec![Some("net_write_timeout".to_owned()), Some("60".to_owned())],
                    vec![Some("interactive_timeout".to_owned()), Some("28800".to_owned())],
                    vec![Some("wait_timeout".to_owned()), Some("28800".to_owned())],
                    vec![Some("sql_mode".to_owned()), Some("STRICT_TRANS_TABLES".to_owned())],
                ],
            );
        }

        // SHOW STATUS
        if sql_upper.starts_with("SHOW STATUS") || sql_upper.starts_with("SHOW GLOBAL STATUS") {
            return QueryResult::rows(
                vec!["Variable_name", "Value"],
                vec![
                    vec![Some("Uptime".to_owned()), Some("0".to_owned())],
                    vec![Some("Threads_connected".to_owned()), Some("1".to_owned())],
                ],
            );
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
                self.create_table(db_name, create.name, create.columns, create.if_not_exists)
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
            Statement::Update { table, assignments, selection, .. } => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.update(db_name, &table.relation.to_string(), assignments, selection.as_ref())
            }
            Statement::Delete(del) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                let table_name = match &del.from {
                    sqlparser::ast::FromTable::WithFromKeyword(tables)
                    | sqlparser::ast::FromTable::WithoutKeyword(tables) => {
                        tables.first().map(|t| t.relation.to_string()).unwrap_or_default()
                    }
                };
                self.delete(db_name, &table_name, del.selection.as_ref())
            }
            Statement::Use(u) => {
                // USE db just returns OK — the session tracks current_db
                let _ = u;
                QueryResult::ok(0, 0)
            }
            _ => QueryResult::err(1295, "Statement not yet supported"),
        }
    }

    pub fn ensure_database(&self, name: &str) {
        let mut dbs = self.databases.write().unwrap_or_else(|e| e.into_inner());
        dbs.entry(name.to_string()).or_insert_with(|| {
            Arc::new(RwLock::new(Database { name: name.to_string(), tables: HashMap::new() }))
        });
    }

    fn create_database(&self, name: &str) -> QueryResult {
        let mut dbs = self.databases.write().unwrap_or_else(|e| e.into_inner());
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
        if_not_exists: bool,
    ) -> QueryResult {
        let parts: Vec<String> = name.0.iter()
            .map(|p| p.as_ident().map(|i| i.value.clone()).unwrap_or_default())
            .collect();
        let (db_name, table_name) = if parts.len() >= 2 {
            (parts[parts.len()-2].clone(), parts[parts.len()-1].clone())
        } else {
            (db_name.to_owned(), parts.last().cloned().unwrap_or_default())
        };

        let columns: Vec<Column> = col_defs.iter().map(|c| {
            let col_type = sql_type_to_col_type(&c.data_type);
            Column {
                name: c.name.value.clone(),
                col_type,
                nullable: true,
                primary_key: false,
            }
        }).collect();

        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        if let Some(db_arc) = dbs.get(&db_name) {
            let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
            if if_not_exists && db.tables.contains_key(&table_name) {
                return QueryResult::ok(0, 0);
            }
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

        // Handle db.table qualified names
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else {
            (db_name.to_owned(), table_name.to_owned())
        };
        let db_name = &eff_db;
        let table_name = &eff_table;
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(db_name.as_str()) else {
            return QueryResult::err(1049, &format!("Unknown database '{db_name}'"));
        };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(table_name.as_str()) else {
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
        let SetExpr::Select(sel) = *query.body else {
            return QueryResult::err(1295, "Complex SELECT not yet supported");
        };

        if sel.from.is_empty() {
            let cols: Vec<String> = sel.projection.iter().map(|p| p.to_string()).collect();
            let vals: Vec<Option<String>> = sel.projection.iter().map(|p| {
                match p {
                    SelectItem::UnnamedExpr(Expr::Value(ref vs)) => {
                        Some(vs.value.to_string().trim_matches('\'').to_owned())
                    }
                    SelectItem::UnnamedExpr(Expr::Function(f)) => Some(f.to_string()),
                    _ => Some(p.to_string()),
                }
            }).collect();
            return QueryResult::rows(cols, vec![vals]);
        }

        let raw_table = sel.from[0].relation.to_string();
        let (sel_db, table_name) = if let Some(dot) = raw_table.find('.') {
            (raw_table[..dot].trim_matches('`').to_owned(), raw_table[dot+1..].trim_matches('`').to_owned())
        } else {
            (db_name.to_owned(), raw_table.trim_matches('`').to_owned())
        };
        let db_name = sel_db;
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&db_name) else {
            return QueryResult::err(1049, &format!("Unknown database '{db_name}'"));
        };
        let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get(&table_name) else {
            return QueryResult::err(1146, &format!("Table '{db_name}.{table_name}' doesn't exist"));
        };

        // Aggregate-only projection
        let is_aggregate_only = !sel.projection.is_empty() && sel.projection.iter().all(|p| {
            matches!(p,
                SelectItem::UnnamedExpr(Expr::Function(_))
                | SelectItem::ExprWithAlias { expr: Expr::Function(_), .. })
        });

        if is_aggregate_only {
            // Filter first if WHERE present
            let filtered: Vec<&Row> = table.rows.iter()
                .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &table.columns, w)))
                .collect();

            let agg_cols: Vec<String> = sel.projection.iter().map(|p| {
                match p {
                    SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                    other => other.to_string(),
                }
            }).collect();
            let agg_vals: Vec<Option<String>> = sel.projection.iter().map(|p| {
                let func = match p {
                    SelectItem::UnnamedExpr(Expr::Function(f)) => f,
                    SelectItem::ExprWithAlias { expr: Expr::Function(f), .. } => f,
                    _ => return None,
                };
                let fname = func.name.to_string().to_uppercase();
                match fname.as_str() {
                    "COUNT" => Some(filtered.len().to_string()),
                    "MAX" => {
                        let col_name = func.args.to_string().trim_matches(|c: char| c.is_whitespace()).to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.and_then(|idx| {
                            filtered.iter().filter_map(|r| r.get(idx)).filter_map(|v| {
                                if let Value::Int(n) = v { Some(*n) } else { None }
                            }).max().map(|v| v.to_string())
                        })
                    }
                    "MIN" => {
                        let col_name = func.args.to_string().trim_matches(|c: char| c.is_whitespace()).to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.and_then(|idx| {
                            filtered.iter().filter_map(|r| r.get(idx)).filter_map(|v| {
                                if let Value::Int(n) = v { Some(*n) } else { None }
                            }).min().map(|v| v.to_string())
                        })
                    }
                    "SUM" => {
                        let col_name = func.args.to_string().trim_matches(|c: char| c.is_whitespace()).to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.map(|idx| {
                            filtered.iter().filter_map(|r| r.get(idx)).filter_map(|v| {
                                if let Value::Int(n) = v { Some(*n) } else { None }
                            }).sum::<i64>().to_string()
                        })
                    }
                    _ => Some("0".to_string()),
                }
            }).collect();
            return QueryResult::rows(agg_cols, vec![agg_vals]);
        }

        // Column projection
        let proj_cols: Vec<(String, usize)> = if sel.projection.iter().any(|p| matches!(p, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..))) {
            table.columns.iter().enumerate().map(|(i, c)| (c.name.clone(), i)).collect()
        } else {
            sel.projection.iter().filter_map(|p| {
                let col_name = match p {
                    SelectItem::UnnamedExpr(Expr::Identifier(id)) => id.value.clone(),
                    SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                        parts.last().map(|i| i.value.clone()).unwrap_or_default()
                    }
                    SelectItem::ExprWithAlias { alias, expr: Expr::Identifier(id), .. } => {
                        let _ = id;
                        alias.value.clone()
                    }
                    _ => return None,
                };
                // Find index by original name (even if aliased)
                let orig_name = match p {
                    SelectItem::ExprWithAlias { expr: Expr::Identifier(id), .. } => id.value.clone(),
                    SelectItem::UnnamedExpr(Expr::Identifier(id)) => id.value.clone(),
                    SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                        parts.last().map(|i| i.value.clone()).unwrap_or_default()
                    }
                    _ => col_name.clone(),
                };
                let idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&orig_name))?;
                Some((col_name, idx))
            }).collect()
        };

        let col_names: Vec<String> = proj_cols.iter().map(|(n, _)| n.clone()).collect();

        // Filter by WHERE
        let mut result_rows: Vec<Vec<Option<String>>> = table.rows.iter()
            .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &table.columns, w)))
            .map(|row| proj_cols.iter().map(|(_, idx)| row.get(*idx).and_then(|v| v.to_display())).collect())
            .collect();

        // ORDER BY
        if let Some(ob) = &query.order_by {
            if let sqlparser::ast::OrderByKind::Expressions(exprs) = &ob.kind {
                for order_expr in exprs.iter().rev() {
                    let col_name = order_expr.expr.to_string();
                    if let Some(idx) = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name)) {
                        let asc = order_expr.options.asc.unwrap_or(true);
                        let proj_idx = proj_cols.iter().position(|(_, i)| *i == idx);
                        if let Some(pidx) = proj_idx {
                            result_rows.sort_by(|a, b| {
                                let av = a.get(pidx).and_then(|x| x.as_deref());
                                let bv = b.get(pidx).and_then(|x| x.as_deref());
                                let ord = match (av, bv) {
                                    (Some(x), Some(y)) => {
                                        match (x.parse::<i64>(), y.parse::<i64>()) {
                                            (Ok(xi), Ok(yi)) => xi.cmp(&yi),
                                            _ => x.cmp(y),
                                        }
                                    }
                                    (None, Some(_)) => std::cmp::Ordering::Less,
                                    (Some(_), None) => std::cmp::Ordering::Greater,
                                    (None, None) => std::cmp::Ordering::Equal,
                                };
                                if asc { ord } else { ord.reverse() }
                            });
                        }
                    }
                }
            }
        }

        // LIMIT / OFFSET
        let offset = query.offset.as_ref().and_then(|o| {
            if let Expr::Value(ref v) = o.value {
                v.value.to_string().parse::<usize>().ok()
            } else { None }
        }).unwrap_or(0);
        let limit = query.limit.as_ref().and_then(|l| {
            if let Expr::Value(ref v) = l {
                v.value.to_string().parse::<usize>().ok()
            } else { None }
        });

        let result_rows: Vec<_> = result_rows.into_iter().skip(offset).collect();
        let result_rows: Vec<_> = if let Some(n) = limit {
            result_rows.into_iter().take(n).collect()
        } else {
            result_rows
        };

        QueryResult::rows(col_names, result_rows)
    }

    fn update(&self, db_name: &str, table_name: &str, assignments: Vec<Assignment>, selection: Option<&Expr>) -> QueryResult {
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else {
            (db_name.to_owned(), table_name.trim_matches('`').to_owned())
        };
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&eff_db) else {
            return QueryResult::err(1049, &format!("Unknown database '{eff_db}'"));
        };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(&eff_table) else {
            return QueryResult::err(1146, &format!("Table '{eff_db}.{eff_table}' doesn't exist"));
        };

        let mut affected = 0u64;
        for row in table.rows.iter_mut() {
            if selection.map_or(true, |w| eval_where(row, &table.columns, w)) {
                for asgn in &assignments {
                    let col_name = asgn.target.to_string();
                    if let Some(idx) = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name)) {
                        row[idx] = expr_to_value(asgn.value.clone());
                    }
                }
                affected += 1;
            }
        }
        QueryResult::ok(affected, 0)
    }

    fn delete(&self, db_name: &str, table_name: &str, selection: Option<&Expr>) -> QueryResult {
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else {
            (db_name.to_owned(), table_name.trim_matches('`').to_owned())
        };
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&eff_db) else {
            return QueryResult::err(1049, &format!("Unknown database '{eff_db}'"));
        };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(&eff_table) else {
            return QueryResult::err(1146, &format!("Table '{eff_db}.{eff_table}' doesn't exist"));
        };

        let before = table.rows.len();
        table.rows.retain(|row| {
            selection.map_or(false, |w| !eval_where(row, &table.columns, w))
        });
        let affected = (before - table.rows.len()) as u64;
        QueryResult::ok(affected, 0)
    }

    /// Generate a SQL dump of all user databases (excludes system schemas).
    pub fn dump_sql(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let system_dbs = ["information_schema", "performance_schema", "mysql", "sys", "test"];
        let mut out = String::new();
        out.push_str("-- RunAlexDB SQL dump\n");
        out.push_str(&format!("-- Generated: unix_ts={}\n\n", ts));

        for (db_name, db_arc) in dbs.iter() {
            if system_dbs.contains(&db_name.as_str()) { continue; }
            out.push_str(&format!("CREATE DATABASE IF NOT EXISTS `{}`;\n", db_name));
            out.push_str(&format!("USE `{}`;\n\n", db_name));

            let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
            for (tname, table) in &db.tables {
                out.push_str(&format!("CREATE TABLE IF NOT EXISTS `{}` (\n", tname));
                let col_defs: Vec<String> = table.columns.iter().map(|c| {
                    let type_str: String = match &c.col_type {
                        ColumnType::Int => "INT".into(),
                        ColumnType::BigInt => "BIGINT".into(),
                        ColumnType::Float => "DOUBLE".into(),
                        ColumnType::VarChar(n) => format!("VARCHAR({})", n),
                        ColumnType::Text => "TEXT".into(),
                        ColumnType::Blob => "BLOB".into(),
                        ColumnType::Timestamp => "TIMESTAMP".into(),
                    };
                    let pk = if c.primary_key { " PRIMARY KEY" } else { "" };
                    format!("  `{}` {}{}", c.name, type_str, pk)
                }).collect();
                out.push_str(&col_defs.join(",\n"));
                out.push_str("\n);\n\n");

                if !table.rows.is_empty() {
                    let col_names: Vec<String> = table.columns.iter().map(|c| format!("`{}`", c.name)).collect();
                    out.push_str(&format!("INSERT INTO `{}` ({}) VALUES\n", tname, col_names.join(", ")));
                    let row_strs: Vec<String> = table.rows.iter().map(|row| {
                        let vals: Vec<String> = row.iter().map(|v| match v {
                            Value::Null => "NULL".into(),
                            Value::Int(i) => i.to_string(),
                            Value::Float(f) => f.to_string(),
                            Value::Text(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
                            Value::Bytes(b) => format!("X'{}'", hex::encode(b)),
                        }).collect();
                        format!("  ({})", vals.join(", "))
                    }).collect();
                    out.push_str(&row_strs.join(",\n"));
                    out.push_str(";\n\n");
                }
            }
        }
        out
    }

    /// Restore from a SQL dump. Executes each statement sequentially.
    pub fn restore_sql(&self, sql_dump: &str) {
        let mut current_db: Option<String> = None;
        let mut batch = String::new();
        for line in sql_dump.lines() {
            let line = line.trim();
            if line.starts_with("--") || line.is_empty() { continue; }
            batch.push_str(line);
            batch.push(' ');
            if line.ends_with(';') {
                let stmt = batch.trim().to_owned();
                batch.clear();
                let upper = stmt.to_uppercase();
                if upper.starts_with("USE ") {
                    let db_name = stmt[4..].trim().trim_end_matches(';').trim_matches('`').to_owned();
                    current_db = Some(db_name);
                    continue;
                }
                let _ = self.execute(&stmt, &current_db);
            }
        }
    }
}

// ── WHERE evaluator ────────────────────────────────────────────────────────

fn eval_row_expr(row: &Row, cols: &[Column], expr: &Expr) -> Value {
    match expr {
        Expr::Value(vs) => expr_to_value(Expr::Value(vs.clone())),
        Expr::Identifier(id) => {
            cols.iter().position(|c| c.name.eq_ignore_ascii_case(&id.value))
                .and_then(|idx| row.get(idx).cloned())
                .unwrap_or(Value::Null)
        }
        Expr::CompoundIdentifier(parts) => {
            if let Some(last) = parts.last() {
                cols.iter().position(|c| c.name.eq_ignore_ascii_case(&last.value))
                    .and_then(|idx| row.get(idx).cloned())
                    .unwrap_or(Value::Null)
            } else { Value::Null }
        }
        _ => Value::Null,
    }
}

fn values_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => x.cmp(y),
        (Value::Float(x), Value::Float(y)) => x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal),
        (Value::Int(x), Value::Float(y)) => (*x as f64).partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal),
        (Value::Float(x), Value::Int(y)) => x.partial_cmp(&(*y as f64)).unwrap_or(std::cmp::Ordering::Equal),
        (Value::Text(x), Value::Text(y)) => x.cmp(y),
        (Value::Null, Value::Null) => std::cmp::Ordering::Equal,
        (Value::Null, _) => std::cmp::Ordering::Less,
        (_, Value::Null) => std::cmp::Ordering::Greater,
        _ => {
            let xs = a.to_display().unwrap_or_default();
            let ys = b.to_display().unwrap_or_default();
            xs.cmp(&ys)
        }
    }
}

fn values_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Null, _) | (_, Value::Null) => false,
        _ => values_cmp(a, b) == std::cmp::Ordering::Equal,
    }
}

fn like_match(value: &str, pattern: &str) -> bool {
    // Simple LIKE — % = any sequence, _ = one char
    let vi = value.chars().collect::<Vec<_>>();
    let pi = pattern.chars().collect::<Vec<_>>();
    fn rec(v: &[char], p: &[char]) -> bool {
        if p.is_empty() { return v.is_empty(); }
        if p[0] == '%' {
            // Skip consecutive %
            let next_p = &p[1..];
            for i in 0..=v.len() {
                if rec(&v[i..], next_p) { return true; }
            }
            false
        } else if p[0] == '_' {
            !v.is_empty() && rec(&v[1..], &p[1..])
        } else {
            !v.is_empty() && p[0].to_lowercase().eq(v[0].to_lowercase()) && rec(&v[1..], &p[1..])
        }
    }
    rec(&vi, &pi)
}

fn eval_where(row: &Row, cols: &[Column], expr: &Expr) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            match op {
                BinaryOperator::And => {
                    return eval_where(row, cols, left) && eval_where(row, cols, right);
                }
                BinaryOperator::Or => {
                    return eval_where(row, cols, left) || eval_where(row, cols, right);
                }
                _ => {}
            }
            let l = eval_row_expr(row, cols, left);
            let r = eval_row_expr(row, cols, right);
            match op {
                BinaryOperator::Eq      => values_eq(&l, &r),
                BinaryOperator::NotEq   => !values_eq(&l, &r),
                BinaryOperator::Lt      => values_cmp(&l, &r) == std::cmp::Ordering::Less,
                BinaryOperator::LtEq    => values_cmp(&l, &r) != std::cmp::Ordering::Greater,
                BinaryOperator::Gt      => values_cmp(&l, &r) == std::cmp::Ordering::Greater,
                BinaryOperator::GtEq    => values_cmp(&l, &r) != std::cmp::Ordering::Less,
                _ => true,
            }
        }
        Expr::IsNull(e) => matches!(eval_row_expr(row, cols, e), Value::Null),
        Expr::IsNotNull(e) => !matches!(eval_row_expr(row, cols, e), Value::Null),
        Expr::Like { expr, pattern, negated, .. } => {
            let val = eval_row_expr(row, cols, expr);
            let pat = eval_row_expr(row, cols, pattern);
            if let (Some(v), Some(p)) = (val.as_str(), pat.as_str()) {
                let m = like_match(v, p);
                if *negated { !m } else { m }
            } else { false }
        }
        Expr::Nested(e) => eval_where(row, cols, e),
        Expr::UnaryOp { op: UnaryOperator::Not, expr } => !eval_where(row, cols, expr),
        Expr::Between { expr, low, high, negated } => {
            let v = eval_row_expr(row, cols, expr);
            let lo = eval_row_expr(row, cols, low);
            let hi = eval_row_expr(row, cols, high);
            let in_range = values_cmp(&v, &lo) != std::cmp::Ordering::Less
                && values_cmp(&v, &hi) != std::cmp::Ordering::Greater;
            if *negated { !in_range } else { in_range }
        }
        Expr::InList { expr, list, negated } => {
            let v = eval_row_expr(row, cols, expr);
            let found = list.iter().any(|item| values_eq(&v, &eval_row_expr(row, cols, item)));
            if *negated { !found } else { found }
        }
        _ => true,
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

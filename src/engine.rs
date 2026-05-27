//! In-memory SQL engine — tables, rows, query dispatch.

use subtle::ConstantTimeEq;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, OnceLock};
use dashmap::DashMap;

use anyhow::{bail, Result};
use sqlparser::ast::{
    Assignment, BinaryOperator, ColumnDef, Expr, ObjectName,
    Query, SelectItem, SetExpr, Statement, UnaryOperator, Values,
};

use crate::config::Config;

// ── Query statement cache (avoids repeated sqlparser parsing) ─────────────
// Key: CRC32 hash of the SQL string. Value: cloned AST Arc.
static STMT_CACHE: OnceLock<DashMap<u64, Arc<Vec<Statement>>>> = OnceLock::new();

#[inline]
fn stmt_cache() -> &'static DashMap<u64, Arc<Vec<Statement>>> {
    STMT_CACHE.get_or_init(|| DashMap::with_capacity(4096))
}

fn parse_cached(sql: &str) -> Result<Arc<Vec<Statement>>, String> {
    let key = crate::simd_scan::hash_query(sql.as_bytes());
    if let Some(r) = stmt_cache().get(&key) {
        return Ok(Arc::clone(r.value()));
    }
    let dialect = sqlparser::dialect::MySqlDialect {};
    match sqlparser::parser::Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => {
            let arc = Arc::new(stmts);
            if stmt_cache().len() > 8192 { stmt_cache().clear(); }
            stmt_cache().insert(key, Arc::clone(&arc));
            Ok(arc)
        }
        Err(e) => Err(format!("Parse error: {e}")),
    }
}



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
    pub fn into_text(self) -> Option<String> {
        match self {
            Value::Text(s) => Some(s),
            Value::Int(i) => Some(i.to_string()),
            Value::Float(f) => Some(f.to_string()),
            Value::Null => None,
            _ => None,
        }
    }
    pub fn into_int(self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(i),
            Value::Float(f) => Some(f as i64),
            Value::Text(s) => s.trim().parse::<i64>().ok(),
            _ => None,
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
    /// Index of the PRIMARY KEY column, if any.
    pub pk_col_idx: Option<usize>,
    /// Maps pk_value (as String) → row index in `rows`. O(1) PK lookups.
    pub pk_index: HashMap<String, usize>,
    /// Column-oriented int64 store for AVX2 scans.
    /// col_int_data[col_idx] = Some(vec) for Int/BigInt columns, None otherwise.
    pub col_int_data: Vec<Option<Vec<i64>>>,
    /// Column-oriented string store for SIMD/vectorised text scans.
    /// col_str_data[col_idx] = Some(vec) for Text/VarChar columns, None otherwise.
    pub col_str_data: Vec<Option<Vec<String>>>,
    pub next_auto: i64,
}

#[derive(Debug)]
pub struct Database {
    pub name: String,
    pub tables: HashMap<String, Table>,
}

// ── Engine ─────────────────────────────────────────────────────────────────

/// Per-user credentials and privileges.
#[derive(Clone, Debug)]
pub struct DbUser {
    pub password_sha1_sha1: Vec<u8>, // SHA1(SHA1(password)) for native_password auth
    /// None = all databases; Some(set) = whitelist
    pub allowed_dbs: Option<std::collections::HashSet<String>>,
    pub can_write: bool, // false = SELECT only
    pub is_root: bool,
}

pub struct Engine {
    pub databases: RwLock<HashMap<String, Arc<RwLock<Database>>>>,
    /// MySQL user accounts: username → DbUser
    pub users: RwLock<HashMap<String, DbUser>>,
    /// Global write generation counter. Incremented on every INSERT/UPDATE/DELETE.
    /// Per-connection L0 cache checks this to detect cross-connection invalidation.
    pub write_gen: std::sync::atomic::AtomicU64,
    /// Last auto-generated or inserted PK value (per MySQL semantics).
    pub last_insert_id: std::sync::atomic::AtomicU64,
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
        // Initialise root user from config password
        let mut users = HashMap::new();
        let root_hash = double_sha1(cfg.auth.root_password.as_bytes());
        users.insert("root".to_owned(), DbUser {
            password_sha1_sha1: root_hash,
            allowed_dbs: None,
            can_write: true,
            is_root: true,
        });
        let engine = Self {
            databases: RwLock::new(dbs),
            users: RwLock::new(users),
            write_gen: std::sync::atomic::AtomicU64::new(0),
            last_insert_id: std::sync::atomic::AtomicU64::new(0),
        };

        // Auto-load persisted data on startup
        let persist_path = format!("{}/runalexdb.sql", cfg.data_dir);
        if let Ok(sql) = std::fs::read_to_string(&persist_path) {
            tracing::info!("Loading persisted data from {persist_path}");
            engine.restore_sql(&sql);
        }

        engine
    }

    /// Increment write generation counter (called after any INSERT/UPDATE/DELETE).
    #[inline(always)]
    pub fn take_snapshot(&self) -> std::collections::HashMap<String, std::collections::HashMap<String, Table>> {
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let mut snap = std::collections::HashMap::new();
        for (db_name, db_arc) in dbs.iter() {
            let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
            snap.insert(db_name.clone(), db.tables.clone());
        }
        snap
    }

    pub fn restore_snapshot(&self, snap: std::collections::HashMap<String, std::collections::HashMap<String, Table>>) {
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        for (db_name, tables) in snap {
            if let Some(db_arc) = dbs.get(&db_name) {
                let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
                db.tables = tables;
            }
        }
        self.bump_write_gen();
    }

    pub fn bump_write_gen(&self) {
        self.write_gen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Current write generation (for L0 cache validity checks).
    #[inline(always)]
    pub fn write_gen(&self) -> u64 {
        self.write_gen.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Execute a SQL statement string in the context of `current_db`.
    pub fn execute(&self, sql: &str, current_db: &Option<String>, user_name: &str) -> QueryResult {
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
        if sql_upper.trim_end_matches(';') == "SELECT DATABASE()"
            || sql_upper.trim_end_matches(';') == "SELECT SCHEMA()"
            || sql_upper.trim_end_matches(';') == "SELECT DATABASE() AS DATABASE()"
        {
            let db = current_db.as_deref().unwrap_or("");
            let col = if sql_upper.contains("SCHEMA") { "SCHEMA()" } else { "DATABASE()" };
            return QueryResult::rows(
                vec![col],
                vec![vec![if db.is_empty() { None } else { Some(db.to_owned()) }]],
            );
        }
        // ── User DDL (not in sqlparser) ──────────────────────────────────────
        if sql_upper.starts_with("CREATE USER") {
            return self.exec_create_user(sql.trim());
        }
        if sql_upper.starts_with("DROP USER") {
            return self.exec_drop_user(sql.trim());
        }
        if sql_upper.starts_with("GRANT ") {
            return self.exec_grant(sql.trim());
        }
        if sql_upper.starts_with("REVOKE ") {
            return self.exec_revoke(sql.trim());
        }
        if sql_upper.starts_with("SHOW GRANTS") {
            return self.exec_show_grants(sql.trim());
        }
        if sql_upper.starts_with("SHOW USERS") || sql_upper == "SELECT USER FROM MYSQL.USER" {
            let users = self.users.read().unwrap_or_else(|e| e.into_inner());
            let rows: Vec<_> = users.keys().map(|u| vec![Some(u.clone())]).collect();
            return QueryResult::rows(vec!["User"], rows);
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

        // MySQL system variables — SELECT @@var or SELECT @@session.var
        if sql_upper.starts_with("SELECT @@") {
            return self.exec_select_sysvar(sql.trim());
        }

        // LAST_INSERT_ID()
        if sql_upper.starts_with("SELECT LAST_INSERT_ID()") {
            let id = self.last_insert_id.load(std::sync::atomic::Ordering::Relaxed);
            return QueryResult::rows(vec!["LAST_INSERT_ID()"], vec![vec![Some(id.to_string())]]);
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

        // Parse with sqlparser (AST cached by CRC32 key — avoids re-parse on hot queries)
        let stmts = match parse_cached(sql) {
            Ok(s) => s,
            Err(e) => return QueryResult::err(1064, &e),
        };
        // ── Privilege check ──────────────────────────────────────────────────
        {
            let users = self.users.read().unwrap_or_else(|e| e.into_inner());
            if let Some(user) = users.get(user_name) {
                if let (Some(ref allowed), Some(ref db)) = (&user.allowed_dbs, current_db) {
                    if !allowed.contains(db) {
                        return QueryResult::err(1044, &format!(
                            "Access denied for user '{}' to database '{}'", user_name, db
                        ));
                    }
                }
                if !user.can_write {
                    let needs_write = stmts.iter().any(|s| matches!(s,
                        Statement::Insert(_)
                        | Statement::Update { .. }
                        | Statement::Delete(_)
                        | Statement::CreateTable(_)
                        | Statement::CreateDatabase { .. }
                        | Statement::Drop { .. }
                    ));
                    if needs_write {
                        return QueryResult::err(1142, "Command denied to user (no write privilege)");
                    }
                }
            }
        }
        let mut eff_db: Option<String> = current_db.clone();
        let mut last = QueryResult::ok(0, 0);
        for stmt in stmts.iter() {
            // Track USE db changes within a multi-statement batch
            if let Statement::Use(sqlparser::ast::Use::Object(obj_name)) = stmt {
                let db = obj_name.to_string();
                eff_db = Some(db.trim_matches('`').to_owned());
            }
            last = self.exec_stmt(stmt.clone(), &eff_db);
            // Bump write generation for DML (enables L0 cache cross-connection invalidation)
            if matches!(last, QueryResult::Ok { .. }) {
                self.bump_write_gen();
            }
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
                let col_names: Vec<String> = insert.columns.iter().map(|c| c.value.clone()).collect();
                self.insert(db_name, &insert.table.to_string(), insert.source, insert.replace_into, col_names)
            }
            Statement::Query(q) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.select(db_name, *q)
            }
            Statement::Drop { object_type, names, if_exists, .. } => {
                use sqlparser::ast::ObjectType;
                let db_name = current_db.as_deref().unwrap_or("test");
                match object_type {
                    ObjectType::Table => {
                        let mut dbs = self.databases.write().unwrap_or_else(|e| e.into_inner());
                        for name in &names {
                            let raw = name.to_string();
                            let (tdb, tname) = if let Some(dot) = raw.find('.') {
                                (raw[..dot].trim_matches('`').to_owned(), raw[dot+1..].trim_matches('`').to_owned())
                            } else {
                                (db_name.to_owned(), raw.trim_matches('`').to_owned())
                            };
                            if let Some(db_arc) = dbs.get(&tdb) {
                                let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
                                if db.tables.remove(&tname).is_none() && !if_exists {
                                    return QueryResult::err(1051, &format!("Unknown table '{}.{}'", tdb, tname));
                                }
                            } else if !if_exists {
                                return QueryResult::err(1049, &format!("Unknown database '{}'", tdb));
                            }
                        }
                        self.bump_write_gen();
                        QueryResult::ok(0, 0)
                    }
                    ObjectType::Database | ObjectType::Schema => {
                        let mut dbs = self.databases.write().unwrap_or_else(|e| e.into_inner());
                        for name in &names {
                            let dbname = name.to_string().trim_matches('`').to_owned();
                            if dbs.remove(&dbname).is_none() && !if_exists {
                                return QueryResult::err(1049, &format!("Unknown database '{}'", dbname));
                            }
                        }
                        self.bump_write_gen();
                        QueryResult::ok(0, 0)
                    }
                    _ => QueryResult::ok(0, 0),
                }
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
            Statement::Truncate { table_names, .. } => {
                let name = table_names.first().map(|t| t.name.to_string()).unwrap_or_default();
                let (eff_db, eff_table) = if let Some(dot) = name.find('.') {
                    (name[..dot].trim_matches('`').to_owned(), name[dot+1..].trim_matches('`').to_owned())
                } else {
                    let db = current_db.clone().unwrap_or_default();
                    (db, name.trim_matches('`').to_owned())
                };
                let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
                let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
                let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
                let Some(table) = db.tables.get_mut(&eff_table) else { return QueryResult::err(1146, "Table not found"); };
                let affected = table.rows.len() as u64;
                table.rows.clear();
                table.pk_index.clear();
                for store in table.col_int_data.iter_mut().flatten() { store.clear(); }
                for store in table.col_str_data.iter_mut().flatten() { store.clear(); }
                self.bump_write_gen();
                QueryResult::ok(affected, 0)
            }
            Statement::ExplainTable { table_name, .. } => {
                // DESCRIBE / DESC table_name
                let name = table_name.to_string();
                let (eff_db, eff_table) = if let Some(dot) = name.find('.') {
                    (name[..dot].trim_matches('`').to_owned(), name[dot+1..].trim_matches('`').to_owned())
                } else {
                    (current_db.clone().unwrap_or_else(|| "test".to_owned()), name.trim_matches('`').to_owned())
                };
                let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
                let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
                let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
                let Some(table) = db.tables.get(&eff_table) else { return QueryResult::err(1146, "Table not found"); };
                let cols = vec!["Field", "Type", "Null", "Key", "Default", "Extra"];
                let rows: Vec<Vec<Option<String>>> = table.columns.iter().map(|c| {
                    let type_str = match &c.col_type {
                        ColumnType::Int => "int".to_owned(),
                        ColumnType::BigInt => "bigint".to_owned(),
                        ColumnType::Float => "double".to_owned(),
                        ColumnType::VarChar(n) => format!("varchar({})", n),
                        ColumnType::Text => "text".to_owned(),
                        ColumnType::Blob => "blob".to_owned(),
                        ColumnType::Timestamp => "timestamp".to_owned(),
                    };
                    vec![
                        Some(c.name.clone()),
                        Some(type_str),
                        Some(if c.nullable { "YES" } else { "NO" }.to_owned()),
                        Some(if c.primary_key { "PRI" } else { "" }.to_owned()),
                        None, // Default
                        Some(if c.primary_key { "auto_increment" } else { "" }.to_owned()),
                    ]
                }).collect();
                QueryResult::rows(cols, rows)
            }
            Statement::ShowColumns { full, show_options, .. } => {
                // SHOW COLUMNS FROM table_name
                if let Some(tbl) = show_options.show_in.as_ref().and_then(|si| si.parent_name.as_ref()) {
                    let name = tbl.to_string();
                    let (eff_db, eff_table) = if let Some(dot) = name.find('.') {
                        (name[..dot].trim_matches('`').to_owned(), name[dot+1..].trim_matches('`').to_owned())
                    } else {
                        (current_db.clone().unwrap_or_else(|| "test".to_owned()), name.trim_matches('`').to_owned())
                    };
                    let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
                    let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
                    let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
                    let Some(table) = db.tables.get(&eff_table) else { return QueryResult::err(1146, "Table not found"); };
                    let cols: Vec<&str> = if full {
                        vec!["Field", "Type", "Collation", "Null", "Key", "Default", "Extra", "Privileges", "Comment"]
                    } else {
                        vec!["Field", "Type", "Null", "Key", "Default", "Extra"]
                    };
                    let rows: Vec<Vec<Option<String>>> = table.columns.iter().map(|c| {
                        let type_str = match &c.col_type {
                            ColumnType::Int => "int".to_owned(),
                            ColumnType::BigInt => "bigint".to_owned(),
                            ColumnType::Float => "double".to_owned(),
                            ColumnType::VarChar(n) => format!("varchar({})", n),
                            ColumnType::Text => "text".to_owned(),
                            ColumnType::Blob => "blob".to_owned(),
                            ColumnType::Timestamp => "timestamp".to_owned(),
                        };
                        let is_str = matches!(&c.col_type, ColumnType::VarChar(_) | ColumnType::Text);
                        let collation = if is_str { Some("utf8mb4_general_ci".to_owned()) } else { None };
                        if full {
                            vec![
                                Some(c.name.clone()),
                                Some(type_str),
                                collation,
                                Some(if c.nullable { "YES" } else { "NO" }.to_owned()),
                                Some(if c.primary_key { "PRI" } else { "" }.to_owned()),
                                None,
                                Some(if c.primary_key { "auto_increment" } else { "" }.to_owned()),
                                Some("select,insert,update,references".to_owned()),
                                Some(String::new()),
                            ]
                        } else {
                            vec![
                                Some(c.name.clone()),
                                Some(type_str),
                                Some(if c.nullable { "YES" } else { "NO" }.to_owned()),
                                Some(if c.primary_key { "PRI" } else { "" }.to_owned()),
                                None,
                                Some(if c.primary_key { "auto_increment" } else { "" }.to_owned()),
                            ]
                        }
                    }).collect();
                    return QueryResult::rows(cols, rows);
                }
                QueryResult::err(1295, "SHOW COLUMNS requires FROM table_name")
            }
            Statement::ShowCreate { obj_type, obj_name } => {
                use sqlparser::ast::ShowCreateObject;
                if !matches!(obj_type, ShowCreateObject::Table) {
                    return QueryResult::err(1295, "SHOW CREATE only supported for TABLE");
                }
                let name = obj_name.to_string();
                let (eff_db, eff_table) = if let Some(dot) = name.find('.') {
                    (name[..dot].trim_matches('`').to_owned(), name[dot+1..].trim_matches('`').to_owned())
                } else {
                    (current_db.clone().unwrap_or_else(|| "test".to_owned()), name.trim_matches('`').to_owned())
                };
                let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
                let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
                let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
                let Some(table) = db.tables.get(&eff_table) else { return QueryResult::err(1146, "Table not found"); };
                let mut ddl = format!("CREATE TABLE `{}` (
", eff_table);
                let col_defs: Vec<String> = table.columns.iter().map(|c| {
                    let type_str = match &c.col_type {
                        ColumnType::Int => "int".to_owned(),
                        ColumnType::BigInt => "bigint".to_owned(),
                        ColumnType::Float => "double".to_owned(),
                        ColumnType::VarChar(n) => format!("varchar({})", n),
                        ColumnType::Text => "text".to_owned(),
                        ColumnType::Blob => "blob".to_owned(),
                        ColumnType::Timestamp => "timestamp".to_owned(),
                    };
                    let null_str = if c.nullable { "" } else { " NOT NULL" };
                    let pk_str = if c.primary_key { " PRIMARY KEY" } else { "" };
                    format!("  `{}` {}{}{}", c.name, type_str, null_str, pk_str)
                }).collect();
                ddl.push_str(&col_defs.join(",
"));
                ddl.push_str("
) ENGINE=RunAlexDB");
                QueryResult::rows(vec!["Table", "Create Table"], vec![
                    vec![Some(eff_table), Some(ddl)]
                ])
            }
            Statement::AlterTable { name, operations, .. } => {
                let tname = name.to_string();
                let (eff_db, eff_table) = if let Some(dot) = tname.find('.') {
                    (tname[..dot].trim_matches('`').to_owned(), tname[dot+1..].trim_matches('`').to_owned())
                } else {
                    (current_db.clone().unwrap_or_else(|| "test".to_owned()), tname.trim_matches('`').to_owned())
                };
                let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
                let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
                let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
                let Some(table) = db.tables.get_mut(&eff_table) else { return QueryResult::err(1146, "Table not found"); };
                for op in operations {
                    use sqlparser::ast::AlterTableOperation;
                    match op {
                        AlterTableOperation::AddColumn { column_def, .. } => {
                            let col_name = column_def.name.to_string();
                            if table.columns.iter().any(|c| c.name.eq_ignore_ascii_case(&col_name)) {
                                return QueryResult::err(1060, &format!("Duplicate column name '{col_name}'"));
                            }
                            let col_type = sql_type_to_col_type(&column_def.data_type);
                            let is_int = matches!(col_type, ColumnType::Int | ColumnType::BigInt);
                            let is_str = matches!(col_type, ColumnType::VarChar(_) | ColumnType::Text);
                            // Extend all existing rows with NULL
                            for row in table.rows.iter_mut() {
                                row.push(Value::Null);
                            }
                            // Extend column-oriented stores
                            let new_idx = table.columns.len();
                            if is_int {
                                while table.col_int_data.len() <= new_idx { table.col_int_data.push(None); }
                                let store: Vec<i64> = vec![0i64; table.rows.len()];
                                table.col_int_data[new_idx] = Some(store);
                            } else {
                                while table.col_int_data.len() <= new_idx { table.col_int_data.push(None); }
                            }
                            if is_str {
                                while table.col_str_data.len() <= new_idx { table.col_str_data.push(None); }
                                let store: Vec<String> = vec![String::new(); table.rows.len()];
                                table.col_str_data[new_idx] = Some(store);
                            } else {
                                while table.col_str_data.len() <= new_idx { table.col_str_data.push(None); }
                            }
                            table.columns.push(Column {
                                name: col_name,
                                col_type,
                                nullable: true,
                                primary_key: false,
                            });
                        }
                        AlterTableOperation::DropColumn { column_name, .. } => {
                            let name = column_name.to_string();
                            let Some(drop_idx) = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&name)) else {
                                return QueryResult::err(1091, &format!("Can't DROP COLUMN '{}'", name));
                            };
                            if table.columns[drop_idx].primary_key {
                                return QueryResult::err(1075, "Incorrect table definition: only one primary key allowed");
                            }
                            table.columns.remove(drop_idx);
                            for row in table.rows.iter_mut() {
                                if drop_idx < row.len() { row.remove(drop_idx); }
                            }
                            if drop_idx < table.col_int_data.len() { table.col_int_data.remove(drop_idx); }
                            if drop_idx < table.col_str_data.len() { table.col_str_data.remove(drop_idx); }
                            // Rebuild pk_col_idx after column removal
                            table.pk_col_idx = table.columns.iter().position(|c| c.primary_key);
                        }
                        AlterTableOperation::RenameColumn { old_column_name, new_column_name } => {
                            let old = old_column_name.to_string();
                            let new = new_column_name.to_string();
                            let Some(col) = table.columns.iter_mut().find(|c| c.name.eq_ignore_ascii_case(&old)) else {
                                return QueryResult::err(1054, &format!("Unknown column '{}'", old));
                            };
                            col.name = new;
                        }
                        _ => {} // Other operations silently ignored
                    }
                }
                self.bump_write_gen();
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
            let is_pk = c.options.iter().any(|o| matches!(
                &o.option,
                sqlparser::ast::ColumnOption::Unique { is_primary: true, .. }
            ));
            Column {
                name: c.name.value.clone(),
                col_type,
                nullable: !is_pk,
                primary_key: is_pk,
            }
        }).collect();

        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        if let Some(db_arc) = dbs.get(&db_name) {
            let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
            if if_not_exists && db.tables.contains_key(&table_name) {
                return QueryResult::ok(0, 0);
            }
            let pk_col_idx = columns.iter().position(|c| c.primary_key);
            let n_cols = columns.len();
            let col_int_data: Vec<Option<Vec<i64>>> = columns.iter().map(|c| {
                match c.col_type {
                    ColumnType::Int | ColumnType::BigInt => Some(Vec::new()),
                    _ => None,
                }
            }).collect();
            let col_str_data: Vec<Option<Vec<String>>> = columns.iter().map(|c| {
                match c.col_type {
                    ColumnType::Text | ColumnType::VarChar(_) => Some(Vec::new()),
                    _ => None,
                }
            }).collect();
            db.tables.insert(table_name.clone(), Table {
                name: table_name,
                schema: db_name.to_string(),
                columns,
                rows: vec![],
                pk_col_idx,
                pk_index: HashMap::new(),
                col_int_data,
                col_str_data,
                next_auto: 1,
            });
            QueryResult::ok(0, 0)
        } else {
            QueryResult::err(1049, &format!("Unknown database '{db_name}'"))
        }
    }


    fn resolve_in_subqueries(&self, db_name: &str, expr: Expr) -> Expr {
        match expr {
            Expr::InSubquery { expr: inner, subquery, negated } => {
                let result = self.select(db_name, *subquery);
                let list: Vec<Expr> = match result {
                    QueryResult::Rows { rows, .. } => rows.into_iter()
                        .filter_map(|r| r.into_iter().next().flatten())
                        .map(|s| Expr::Value(sqlparser::ast::ValueWithSpan {
                            value: if s.parse::<i64>().is_ok() {
                                sqlparser::ast::Value::Number(s, false)
                            } else {
                                sqlparser::ast::Value::SingleQuotedString(s)
                            },
                            span: sqlparser::tokenizer::Span { start: sqlparser::tokenizer::Location { line: 0, column: 0 }, end: sqlparser::tokenizer::Location { line: 0, column: 0 } },
                        }))
                        .collect(),
                    QueryResult::ValueRows { rows, .. } => rows.into_iter()
                        .filter_map(|r| r.into_iter().next())
                        .map(|v| Expr::Value(sqlparser::ast::ValueWithSpan {
                            value: match v {
                                Value::Int(n) => sqlparser::ast::Value::Number(n.to_string(), false),
                                Value::Text(s) => sqlparser::ast::Value::SingleQuotedString(s),
                                Value::Float(f) => sqlparser::ast::Value::Number(f.to_string(), false),
                                Value::Null => sqlparser::ast::Value::Null,
                                Value::Bytes(_) => sqlparser::ast::Value::Null,
                            },
                            span: sqlparser::tokenizer::Span { start: sqlparser::tokenizer::Location { line: 0, column: 0 }, end: sqlparser::tokenizer::Location { line: 0, column: 0 } },
                        }))
                        .collect(),
                    _ => vec![],
                };
                Expr::InList { expr: inner, list, negated }
            }
            Expr::BinaryOp { left, op, right } => Expr::BinaryOp {
                left: Box::new(self.resolve_in_subqueries(db_name, *left)),
                op,
                right: Box::new(self.resolve_in_subqueries(db_name, *right)),
            },
            Expr::UnaryOp { op, expr } => Expr::UnaryOp {
                op,
                expr: Box::new(self.resolve_in_subqueries(db_name, *expr)),
            },
            Expr::Subquery(subquery) => {
                // Scalar subquery: execute and replace with the first-row first-column value
                let scalar = match self.select(db_name, *subquery) {
                    QueryResult::Rows { rows, .. } => rows.into_iter()
                        .next().and_then(|r| r.into_iter().next().flatten()),
                    QueryResult::ValueRows { rows, .. } => rows.into_iter()
                        .next().and_then(|r| r.into_iter().next())
                        .and_then(|v| v.to_display()),
                    _ => None,
                };
                let span = sqlparser::tokenizer::Span {
                    start: sqlparser::tokenizer::Location { line: 0, column: 0 },
                    end: sqlparser::tokenizer::Location { line: 0, column: 0 },
                };
                Expr::Value(sqlparser::ast::ValueWithSpan {
                    value: match scalar {
                        None => sqlparser::ast::Value::Null,
                        Some(s) => if s.parse::<i64>().is_ok() {
                            sqlparser::ast::Value::Number(s, false)
                        } else {
                            sqlparser::ast::Value::SingleQuotedString(s)
                        },
                    },
                    span,
                })
            }
            Expr::Nested(e) => Expr::Nested(Box::new(self.resolve_in_subqueries(db_name, *e))),
            other => other,
        }
    }

    fn insert(
        &self,
        db_name: &str,
        table_name: &str,
        source: Option<Box<Query>>,
        replace_into: bool,
        insert_columns: Vec<String>,
    ) -> QueryResult {
        let Some(source) = source else {
            return QueryResult::err(1064, "INSERT without VALUES");
        };

        // Handle db.table qualified names
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else {
            (db_name.to_owned(), table_name.to_owned())
        };
        let db_name = &eff_db;
        let table_name = &eff_table;

        // Resolve source rows — either VALUES(...) or INSERT ... SELECT ...
        let source_rows: Vec<Row> = match *source.body {
            SetExpr::Values(Values { rows, .. }) => {
                rows.into_iter().map(|exprs| exprs.into_iter().map(expr_to_value).collect()).collect()
            }
            body => {
                // INSERT ... SELECT: execute the subquery first (no locks held)
                // Preserve ORDER BY / LIMIT from the original source query by reconstructing it.
                // source.order_by/limit were already consumed in the Box<Query> via source_query.
                let q = sqlparser::ast::Query {
                    body: Box::new(body),
                    order_by: source.order_by,
                    limit: source.limit,
                    offset: source.offset,
                    with: source.with,
                    limit_by: source.limit_by,
                    fetch: source.fetch,
                    locks: source.locks,
                    for_clause: source.for_clause,
                    settings: source.settings,
                    format_clause: source.format_clause,
                };
                // Get target column types for type coercion
                let col_types: Vec<ColumnType> = {
                    let dbs_r = self.databases.read().unwrap_or_else(|e| e.into_inner());
                    dbs_r.get(db_name.as_str())
                        .and_then(|a| {
                            let db2 = a.read().unwrap_or_else(|e| e.into_inner());
                            db2.tables.get(table_name.as_str()).map(|t| t.columns.iter().map(|c| c.col_type.clone()).collect())
                        })
                        .unwrap_or_default()
                };
                let result = self.select(db_name.as_str(), q);
                let str_rows = match result {
                    QueryResult::Rows { rows, .. } => rows,
                    QueryResult::ValueRows { rows, .. } => rows.into_iter().map(|r| r.into_iter().map(|v| v.to_display()).collect()).collect(),
                    other => return other,
                };
                str_rows.into_iter().map(|row| {
                    row.into_iter().enumerate().map(|(i, v)| {
                        match (v, col_types.get(i)) {
                            (None, _) => Value::Null,
                            (Some(s), Some(ColumnType::Int) | Some(ColumnType::BigInt)) =>
                                Value::Int(s.parse().unwrap_or(0)),
                            (Some(s), Some(ColumnType::Float)) =>
                                Value::Float(s.parse().unwrap_or(0.0)),
                            (Some(s), _) => Value::Text(s),
                        }
                    }).collect()
                }).collect()
            }
        };

        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(db_name.as_str()) else {
            return QueryResult::err(1049, &format!("Unknown database '{db_name}'"));
        };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(table_name.as_str()) else {
            return QueryResult::err(1146, &format!("Table '{db_name}.{table_name}' doesn't exist"));
        };

        // Build column position map for named INSERT (col_map[table_col_idx] = Some(src_val_idx))
        let col_map: Vec<Option<usize>> = if !insert_columns.is_empty() {
            table.columns.iter().map(|tc| {
                insert_columns.iter().position(|cn| cn.eq_ignore_ascii_case(&tc.name))
            }).collect()
        } else {
            vec![]
        };

        let count = source_rows.len() as u64;
        for src_row in source_rows {
            // Remap per-row so AUTO_INCREMENT is correct for each row
            let row: Row = if !col_map.is_empty() {
                col_map.iter().enumerate().map(|(tci, src_pos_opt)| {
                    match src_pos_opt {
                        Some(si) => src_row.get(*si).cloned().unwrap_or(Value::Null),
                        None if table.columns[tci].primary_key => {
                            let auto_val = table.next_auto;
                            table.next_auto += 1;
                            Value::Int(auto_val)
                        }
                        None => Value::Null,
                    }
                }).collect()
            } else {
                src_row
            };

            // REPLACE INTO: remove existing row with same PK before inserting
            if replace_into {
                if let Some(pk_idx) = table.pk_col_idx {
                    let pk_key = row_pk_key(&row, pk_idx);
                    if let Some(&old_pos) = table.pk_index.get(&pk_key) {
                        table.rows.remove(old_pos);
                        for store in table.col_int_data.iter_mut().flatten() {
                            if old_pos < store.len() { store.remove(old_pos); }
                        }
                        for store in table.col_str_data.iter_mut().flatten() {
                            if old_pos < store.len() { store.remove(old_pos); }
                        }
                        // Rebuild pk_index after removal (positions shifted)
                        table.pk_index.clear();
                        for (i, r) in table.rows.iter().enumerate() {
                            let k = row_pk_key(r, pk_idx);
                            table.pk_index.insert(k, i);
                        }
                    }
                }
            }
            // Maintain PK index + AUTO_INCREMENT counter
            if let Some(pk_idx) = table.pk_col_idx {
                let pk_key = row_pk_key(&row, pk_idx);
                table.pk_index.insert(pk_key, table.rows.len());
                // Advance next_auto past inserted value
                if let Some(Value::Int(n)) = row.get(pk_idx) {
                    if *n >= table.next_auto { table.next_auto = n + 1; }
                }
            }
            // Maintain column-oriented int store (for AVX2 scans)
            for (ci, store) in table.col_int_data.iter_mut().enumerate() {
                if let Some(ref mut v) = store {
                    let val = match row.get(ci) {
                        Some(Value::Int(n)) => *n,
                        _ => 0,
                    };
                    v.push(val);
                }
            }
            // Maintain column-oriented string store (for SIMD text scans)
            for (ci, store) in table.col_str_data.iter_mut().enumerate() {
                if let Some(ref mut v) = store {
                    let val = match row.get(ci) {
                        Some(Value::Text(s)) => s.clone(),
                        _ => String::new(),
                    };
                    v.push(val);
                }
            }
            table.rows.push(row);
        }
        let pk_val = table.pk_col_idx.and_then(|pk_idx| {
            table.rows.last().and_then(|r| r.get(pk_idx)).and_then(|v| {
                if let Value::Int(n) = v { Some(*n as u64) } else { None }
            })
        }).unwrap_or(0);
        drop(table);
        drop(db);
        drop(dbs);
        self.last_insert_id.store(pk_val, std::sync::atomic::Ordering::Relaxed);
        QueryResult::ok(count, pk_val)
    }

    fn select_joined(
        &self,
        db_name: String,
        sel: Box<sqlparser::ast::Select>,
        order_by: Option<sqlparser::ast::OrderBy>,
        limit: Option<Expr>,
        offset: Option<sqlparser::ast::Offset>,
    ) -> QueryResult {
        use sqlparser::ast::{JoinOperator, JoinConstraint, SelectItem};

        // Extract actual table name without alias (e.g. "users AS u" → "users").
        let raw_base = match &sel.from[0].relation {
            sqlparser::ast::TableFactor::Table { name, .. } => name.to_string(),
            other => other.to_string(),
        };
        let (base_db, base_tbl) = if let Some(dot) = raw_base.find('.') {
            (raw_base[..dot].trim_matches('`').to_owned(), raw_base[dot+1..].trim_matches('`').to_owned())
        } else {
            (db_name.clone(), raw_base.trim_matches('`').to_owned())
        };

        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());

        let (left_cols, left_rows): (Vec<Column>, Vec<Row>) = {
            let Some(db_arc) = dbs.get(&base_db) else {
                return QueryResult::err(1049, &format!("Unknown database '{}'", base_db));
            };
            let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
            let Some(tbl) = db.tables.get(&base_tbl) else {
                return QueryResult::err(1146, &format!("Table '{}' doesn't exist", base_tbl));
            };
            (tbl.columns.clone(), tbl.rows.clone())
        };

        let mut combined_cols: Vec<Column> = left_cols;
        let mut combined_rows: Vec<Row> = left_rows;

        for join in &sel.from[0].joins {
            let right_raw = match &join.relation {
                sqlparser::ast::TableFactor::Table { name, .. } => name.to_string(),
                other => other.to_string(),
            };
            let (right_db_name, right_tbl_name) = if let Some(dot) = right_raw.find('.') {
                (right_raw[..dot].trim_matches('`').to_owned(), right_raw[dot+1..].trim_matches('`').to_owned())
            } else {
                (db_name.clone(), right_raw.trim_matches('`').to_owned())
            };

            let (right_cols, right_rows): (Vec<Column>, Vec<Row>) = {
                let Some(rdb_arc) = dbs.get(&right_db_name) else {
                    return QueryResult::err(1049, &format!("Unknown database '{}'", right_db_name));
                };
                let rdb = rdb_arc.read().unwrap_or_else(|e| e.into_inner());
                let Some(rtbl) = rdb.tables.get(&right_tbl_name) else {
                    return QueryResult::err(1146, &format!("Table '{}' doesn't exist", right_tbl_name));
                };
                (rtbl.columns.clone(), rtbl.rows.clone())
            };

            let existing: std::collections::HashSet<String> =
                combined_cols.iter().map(|c| c.name.to_lowercase()).collect();
            let right_ncols = right_cols.len();
            for c in &right_cols {
                let name = if existing.contains(&c.name.to_lowercase()) {
                    format!("{}.{}", right_tbl_name, c.name)
                } else {
                    c.name.clone()
                };
                combined_cols.push(Column { name, ..c.clone() });
            }

            let (on_expr, is_left) = match &join.join_operator {
                JoinOperator::Join(JoinConstraint::On(e))
                | JoinOperator::Inner(JoinConstraint::On(e))  => (Some(e.clone()), false),
                JoinOperator::Left(JoinConstraint::On(e))
                | JoinOperator::LeftOuter(JoinConstraint::On(e)) => (Some(e.clone()), true),
                JoinOperator::CrossJoin => (None, false),
                _ => (None, false),
            };

            let mut new_rows: Vec<Row> = Vec::new();
            for left_row in &combined_rows {
                let mut matched = false;
                for right_row in &right_rows {
                    let mut combined: Row = left_row.clone();
                    combined.extend_from_slice(right_row);
                    let ok = on_expr.as_ref()
                        .map_or(true, |e| eval_where(&combined, &combined_cols, e));
                    if ok {
                        matched = true;
                        new_rows.push(combined);
                    }
                }
                if !matched && is_left {
                    let mut combined = left_row.clone();
                    combined.extend(std::iter::repeat(Value::Null).take(right_ncols));
                    new_rows.push(combined);
                }
            }
            combined_rows = new_rows;
        }

        drop(dbs);

        let mut filtered: Vec<Row> = combined_rows
            .into_iter()
            .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &combined_cols, w)))
            .collect();

        // Pre-projection sort: handle ORDER BY on columns not in SELECT list
        if let Some(ob) = &order_by {
            if let sqlparser::ast::OrderByKind::Expressions(exprs) = &ob.kind {
                let src_keys: Vec<(usize, bool)> = exprs.iter().rev().filter_map(|oe| {
                    let col_name = match &oe.expr {
                        Expr::Identifier(id) => id.value.clone(),
                        Expr::CompoundIdentifier(parts) =>
                            parts.last().map(|i| i.value.clone()).unwrap_or_default(),
                        other => other.to_string(),
                    };
                    let asc = oe.options.asc.unwrap_or(true);
                    combined_cols.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name))
                        .map(|idx| (idx, asc))
                }).collect();
                for (cidx, asc) in src_keys {
                    filtered.sort_by(|a, b| {
                        let av = a.get(cidx).and_then(|v| v.to_display()).unwrap_or_default();
                        let bv = b.get(cidx).and_then(|v| v.to_display()).unwrap_or_default();
                        let ord = match (av.parse::<i64>(), bv.parse::<i64>()) {
                            (Ok(xi), Ok(yi)) => xi.cmp(&yi),
                            _ => av.cmp(&bv),
                        };
                        if asc { ord } else { ord.reverse() }
                    });
                }
            }
        }

        let is_wildcard = sel.projection.iter().any(|p| {
            matches!(p, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..))
        });
        let (out_names, out_exprs): (Vec<String>, Vec<Expr>) = if is_wildcard {
            (
                combined_cols.iter().map(|c| {
                    c.name.rsplitn(2, '.').next().unwrap_or(&c.name).to_owned()
                }).collect(),
                combined_cols.iter().map(|c| {
                    Expr::Identifier(sqlparser::ast::Ident::new(c.name.clone()))
                }).collect(),
            )
        } else {
            sel.projection.iter().map(|p| match p {
                SelectItem::UnnamedExpr(e) => {
                    let name = match e {
                        Expr::Identifier(id) => id.value.clone(),
                        Expr::CompoundIdentifier(parts) =>
                            parts.last().map(|i| i.value.clone()).unwrap_or_default(),
                        _ => e.to_string(),
                    };
                    (name, e.clone())
                }
                SelectItem::ExprWithAlias { expr, alias } => (alias.value.clone(), expr.clone()),
                _ => ("?".to_owned(), Expr::Identifier(sqlparser::ast::Ident::new("__null__"))),
            }).unzip()
        };

        let mut result_rows: Vec<Vec<Option<String>>> = filtered
            .iter()
            .map(|row| {
                out_exprs.iter()
                    .map(|e| eval_row_expr(row, &combined_cols, e).to_display())
                    .collect()
            })
            .collect();

        if let Some(ob) = &order_by {
            if let sqlparser::ast::OrderByKind::Expressions(exprs) = &ob.kind {
                for order_expr in exprs.iter().rev() {
                    let col_name = order_expr.expr.to_string();
                    if let Some(pidx) = out_names.iter().position(|n| n.eq_ignore_ascii_case(&col_name)) {
                        let asc = order_expr.options.asc.unwrap_or(true);
                        result_rows.sort_by(|a, b| {
                            let av = a.get(pidx).and_then(|x| x.as_deref());
                            let bv = b.get(pidx).and_then(|x| x.as_deref());
                            let ord = match (av, bv) {
                                (Some(x), Some(y)) => match (x.parse::<i64>(), y.parse::<i64>()) {
                                    (Ok(xi), Ok(yi)) => xi.cmp(&yi),
                                    _ => x.cmp(y),
                                },
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

        let offset_n = offset.as_ref().and_then(|o| {
            if let Expr::Value(vs) = &o.value {
                if let sqlparser::ast::Value::Number(n, _) = &vs.value { n.parse::<usize>().ok() }
                else { None }
            } else { None }
        }).unwrap_or(0);
        if offset_n > 0 {
            result_rows = result_rows.into_iter().skip(offset_n).collect();
        }

        if let Some(lim) = &limit {
            if let Expr::Value(vs) = lim {
                if let sqlparser::ast::Value::Number(n, _) = &vs.value {
                    if let Ok(n) = n.parse::<usize>() { result_rows.truncate(n); }
                }
            }
        }

        QueryResult::rows(out_names, result_rows)
    }

    fn select(&self, db_name: &str, query: Query) -> QueryResult {
        // Separate body to allow matching before consuming
        let body = query.body;
        let sel = match *body {
            SetExpr::SetOperation { op, set_quantifier, left, right } => {
                use sqlparser::ast::{SetOperator, SetQuantifier};
                let is_all = matches!(set_quantifier, SetQuantifier::All);
                let mk_q = |b: Box<SetExpr>| Query { body: b, order_by: None, limit: None, offset: None, with: None, limit_by: vec![], fetch: None, locks: vec![], for_clause: None, settings: None, format_clause: None };
                let lr = self.select(db_name, mk_q(left));
                let rr = self.select(db_name, mk_q(right));
                let (cols, mut rows): (Vec<String>, Vec<Vec<Option<String>>>) = match lr {
                    QueryResult::Rows { columns, rows } => (columns, rows),
                    QueryResult::ValueRows { columns, rows } => (columns, rows.into_iter().map(|r| r.into_iter().map(|v| v.to_display()).collect()).collect()),
                    other => return other,
                };
                let right_rows: Vec<Vec<Option<String>>> = match rr {
                    QueryResult::Rows { rows, .. } => rows,
                    QueryResult::ValueRows { rows, .. } => rows.into_iter().map(|r| r.into_iter().map(|v| v.to_display()).collect()).collect(),
                    other => return other,
                };
                rows.extend(right_rows);
                if !is_all { rows.dedup(); }
                return QueryResult::Rows { columns: cols, rows };
            }
            SetExpr::Select(s) => s,
            _ => return QueryResult::err(1295, "Complex SELECT not yet supported"),
        };


        if sel.from.is_empty() {
            let cols: Vec<String> = sel.projection.iter().map(|p| match p {
                SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                _ => p.to_string(),
            }).collect();
            let last_id = self.last_insert_id.load(std::sync::atomic::Ordering::Relaxed);
            let vals: Vec<Option<String>> = sel.projection.iter().map(|p| {
                let expr = match p {
                    SelectItem::UnnamedExpr(e) => e,
                    SelectItem::ExprWithAlias { expr, .. } => expr,
                    _ => return Some(p.to_string()),
                };
                match expr {
                    Expr::Value(ref vs) => Some(vs.value.to_string().trim_matches('\'').to_owned()),
                    Expr::Function(f) => {
                        let fname = f.name.to_string().to_uppercase();
                        match fname.as_str() {
                            "DATABASE" | "SCHEMA" => {
                                if db_name.is_empty() { None } else { Some(db_name.to_owned()) }
                            }
                            "VERSION" => Some("8.0.32-RunAlexDB".to_owned()),
                            "USER" | "CURRENT_USER" | "SESSION_USER" | "SYSTEM_USER" => Some("root@localhost".to_owned()),
                            "CONNECTION_ID" => Some("1".to_owned()),
                            "ROW_COUNT" => Some("0".to_owned()),
                            "LAST_INSERT_ID" => Some(last_id.to_string()),
                            _ => Some(eval_row_expr(&Vec::<Value>::new(), &[], expr).to_display().unwrap_or_else(|| f.to_string())),
                        }
                    }
                    _ => Some(eval_row_expr(&Vec::<Value>::new(), &[], expr).to_display().unwrap_or_else(|| expr.to_string())),
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
        let mut sel = sel;
        if let Some(w) = sel.selection.take() {
            sel.selection = Some(self.resolve_in_subqueries(&db_name, w));
        }
        if !sel.from[0].joins.is_empty() {
            return self.select_joined(db_name, sel, query.order_by, query.limit, query.offset);
        }
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&db_name) else {
            return QueryResult::err(1049, &format!("Unknown database '{db_name}'"));
        };
        let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get(&table_name) else {
            return QueryResult::err(1146, &format!("Table '{db_name}.{table_name}' doesn't exist"));
        };

        // Aggregate-only projection
        let is_agg_fname = |name: &str| matches!(name,
            "COUNT" | "SUM" | "AVG" | "MIN" | "MAX" | "GROUP_CONCAT"
            | "STD" | "STDDEV" | "STDDEV_POP" | "VARIANCE" | "VAR_POP"
            | "BIT_AND" | "BIT_OR" | "BIT_XOR"
        );
        let has_group_by = matches!(&sel.group_by, sqlparser::ast::GroupByExpr::Expressions(exprs, _) if !exprs.is_empty());
        let is_aggregate_only = !sel.projection.is_empty() && !has_group_by && sel.projection.iter().all(|p| {
            let f = match p {
                SelectItem::UnnamedExpr(Expr::Function(f)) => f,
                SelectItem::ExprWithAlias { expr: Expr::Function(f), .. } => f,
                _ => return false,
            };
            is_agg_fname(f.name.to_string().to_uppercase().as_str())
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
                    "COUNT" => {
                        if let sqlparser::ast::FunctionArguments::List(ref list) = func.args {
                            if matches!(list.duplicate_treatment, Some(sqlparser::ast::DuplicateTreatment::Distinct)) {
                                let col_name = list.args.iter().next().and_then(|a| match a {
                                    sqlparser::ast::FunctionArg::Unnamed(fae) => match fae {
                                        sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(id)) => Some(id.value.clone()),
                                        sqlparser::ast::FunctionArgExpr::Expr(Expr::CompoundIdentifier(parts)) => parts.last().map(|i| i.value.clone()),
                                        _ => None,
                                    },
                                    _ => None,
                                }).unwrap_or_default();
                                let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                                let count = col_idx.map(|idx| {
                                    let mut seen = std::collections::HashSet::new();
                                    filtered.iter()
                                        .filter_map(|r| r.get(idx))
                                        .filter(|v| !matches!(v, Value::Null))
                                        .filter_map(|v| v.to_display())
                                        .filter(|k| seen.insert(k.clone()))
                                        .count()
                                }).unwrap_or(0);
                                return Some(count.to_string());
                            }
                        }
                        Some(filtered.len().to_string())
                    }
                    "GROUP_CONCAT" => {
                        let (sep, col_name_opt) = if let sqlparser::ast::FunctionArguments::List(ref list) = func.args {
                            let sep = list.clauses.iter().find_map(|cl| {
                                if let sqlparser::ast::FunctionArgumentClause::Separator(ref sv) = cl {
                                    match sv {
                                        sqlparser::ast::Value::SingleQuotedString(s)
                                        | sqlparser::ast::Value::DoubleQuotedString(s) => Some(s.clone()),
                                        _ => None,
                                    }
                                } else { None }
                            }).unwrap_or_else(|| ",".to_owned());
                            let col = list.args.iter().next().and_then(|a| match a {
                                sqlparser::ast::FunctionArg::Unnamed(fae) => match fae {
                                    sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(id)) => Some(id.value.clone()),
                                    sqlparser::ast::FunctionArgExpr::Expr(Expr::CompoundIdentifier(parts)) => parts.last().map(|i| i.value.clone()),
                                    _ => None,
                                },
                                _ => None,
                            });
                            (sep, col)
                        } else { (",".to_owned(), None) };
                        let col_name = col_name_opt.unwrap_or_default();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.map(|idx| {
                            let parts: Vec<String> = filtered.iter()
                                .filter_map(|r| r.get(idx))
                                .filter_map(|v| v.to_display())
                                .collect();
                            parts.join(&sep)
                        }).filter(|s| !s.is_empty())
                    }
                    "MAX" => {
                        let col_name = func.args.to_string().trim().trim_start_matches("(").trim_end_matches(")").trim().to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.and_then(|idx| {
                            filtered.iter().filter_map(|r| r.get(idx)).filter_map(|v| {
                                if let Value::Int(n) = v { Some(*n) } else { None }
                            }).max().map(|v| v.to_string())
                        })
                    }
                    "MIN" => {
                        let col_name = func.args.to_string().trim().trim_start_matches("(").trim_end_matches(")").trim().to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.and_then(|idx| {
                            filtered.iter().filter_map(|r| r.get(idx)).filter_map(|v| {
                                if let Value::Int(n) = v { Some(*n) } else { None }
                            }).min().map(|v| v.to_string())
                        })
                    }
                    "SUM" => {
                        let col_name = func.args.to_string().trim().trim_start_matches("(").trim_end_matches(")").trim().to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.map(|idx| {
                            filtered.iter().filter_map(|r| r.get(idx)).filter_map(|v| {
                                if let Value::Int(n) = v { Some(*n) } else { None }
                            }).sum::<i64>().to_string()
                        })
                    }
                    "AVG" => {
                        let col_name = func.args.to_string().trim().trim_start_matches("(").trim_end_matches(")").trim().to_owned();
                        let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name));
                        col_idx.and_then(|idx| {
                            let nums: Vec<i64> = filtered.iter().filter_map(|r| r.get(idx))
                                .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                                .collect();
                            if nums.is_empty() { None }
                            else { Some((nums.iter().sum::<i64>() / nums.len() as i64).to_string()) }
                        })
                    }
                    _ => Some("0".to_string()),
                }
            }).collect();
            return QueryResult::rows(agg_cols, vec![agg_vals]);
        }

        // GROUP BY path
        let group_by_cols: Vec<usize> = match &sel.group_by {
            sqlparser::ast::GroupByExpr::Expressions(exprs, _) if !exprs.is_empty() => {
                exprs.iter().filter_map(|e| {
                    let name = match e {
                        Expr::Identifier(id) => id.value.clone(),
                        Expr::CompoundIdentifier(parts) => parts.last().map(|i| i.value.clone()).unwrap_or_default(),
                        _ => return None,
                    };
                    table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&name))
                }).collect()
            }
            _ => vec![],
        };
        if !group_by_cols.is_empty() {
            let filtered: Vec<&Row> = table.rows.iter()
                .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &table.columns, w)))
                .collect();
            let mut groups: std::collections::BTreeMap<Vec<Option<String>>, Vec<&Row>> = std::collections::BTreeMap::new();
            for row in &filtered {
                let key: Vec<Option<String>> = group_by_cols.iter()
                    .map(|&ci| row.get(ci).and_then(|v| v.to_display()))
                    .collect();
                groups.entry(key).or_default().push(row);
            }
            let out_cols: Vec<String> = sel.projection.iter().map(|p| {
                match p {
                    SelectItem::ExprWithAlias { alias, .. } => alias.value.clone(),
                    other => other.to_string(),
                }
            }).collect();
            let eval_group_agg = |f: &sqlparser::ast::Function, rows: &Vec<&Row>| -> Option<String> {
                let fname = f.name.to_string().to_uppercase();
                let col_arg = f.args.to_string().trim().trim_start_matches('(').trim_end_matches(')').trim().to_owned();
                match fname.as_str() {
                    "COUNT" => {
                        if let sqlparser::ast::FunctionArguments::List(ref list) = f.args {
                            if matches!(list.duplicate_treatment, Some(sqlparser::ast::DuplicateTreatment::Distinct)) {
                                let col_arg_clean = list.args.iter().next().and_then(|a| match a {
                                    sqlparser::ast::FunctionArg::Unnamed(fae) => match fae {
                                        sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(id)) => Some(id.value.clone()),
                                        sqlparser::ast::FunctionArgExpr::Expr(Expr::CompoundIdentifier(parts)) => parts.last().map(|i| i.value.clone()),
                                        _ => None,
                                    },
                                    _ => None,
                                }).unwrap_or_default();
                                if col_arg_clean != "*" && !col_arg_clean.is_empty() {
                                    let ci = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg_clean));
                                    return ci.map(|ci| {
                                        let mut seen = std::collections::HashSet::new();
                                        rows.iter()
                                            .filter_map(|r| r.get(ci))
                                            .filter(|v| !matches!(v, Value::Null))
                                            .filter_map(|v| v.to_display())
                                            .filter(|k| seen.insert(k.clone()))
                                            .count().to_string()
                                    }).or_else(|| Some("0".to_owned()));
                                }
                            }
                        }
                        Some(rows.len().to_string())
                    }
                    "GROUP_CONCAT" => {
                        let (sep, col_name_opt) = if let sqlparser::ast::FunctionArguments::List(ref list) = f.args {
                            let sep = list.clauses.iter().find_map(|cl| {
                                if let sqlparser::ast::FunctionArgumentClause::Separator(ref sv) = cl {
                                    match sv {
                                        sqlparser::ast::Value::SingleQuotedString(s)
                                        | sqlparser::ast::Value::DoubleQuotedString(s) => Some(s.clone()),
                                        _ => None,
                                    }
                                } else { None }
                            }).unwrap_or_else(|| ",".to_owned());
                            let col = list.args.iter().next().and_then(|a| match a {
                                sqlparser::ast::FunctionArg::Unnamed(fae) => match fae {
                                    sqlparser::ast::FunctionArgExpr::Expr(Expr::Identifier(id)) => Some(id.value.clone()),
                                    sqlparser::ast::FunctionArgExpr::Expr(Expr::CompoundIdentifier(parts)) => parts.last().map(|i| i.value.clone()),
                                    _ => None,
                                },
                                _ => None,
                            });
                            (sep, col)
                        } else { (",".to_owned(), None) };
                        let ci = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(col_name_opt.as_deref().unwrap_or("")))?;
                        let parts: Vec<String> = rows.iter()
                            .filter_map(|r| r.get(ci))
                            .filter_map(|v| v.to_display())
                            .collect();
                        if parts.is_empty() { None } else { Some(parts.join(&sep)) }
                    }
                    "SUM" => {
                        let ci = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg));
                        ci.map(|ci| rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .sum::<i64>().to_string())
                    }
                    "AVG" => {
                        let ci = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg));
                        ci.and_then(|ci| {
                            let nums: Vec<i64> = rows.iter().filter_map(|r| r.get(ci))
                                .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                                .collect();
                            if nums.is_empty() { None }
                            else { Some((nums.iter().sum::<i64>() / nums.len() as i64).to_string()) }
                        })
                    }
                    "MAX" => {
                        let ci = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg));
                        ci.and_then(|ci| rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .max().map(|v| v.to_string()))
                    }
                    "MIN" => {
                        let ci = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg));
                        ci.and_then(|ci| rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .min().map(|v| v.to_string()))
                    }
                    _ => None,
                }
            };
            let out_rows: Vec<Vec<Option<String>>> = groups.into_iter().filter_map(|(group_key, rows)| {
                let row_vals: Vec<Option<String>> = sel.projection.iter().map(|p| {
                    match p {
                        SelectItem::UnnamedExpr(Expr::Function(f))
                        | SelectItem::ExprWithAlias { expr: Expr::Function(f), .. } => {
                            eval_group_agg(f, &rows)
                        }
                        SelectItem::UnnamedExpr(Expr::Identifier(id)) => {
                            let pos = group_by_cols.iter().enumerate()
                                .find(|(_, &c)| table.columns[c].name.eq_ignore_ascii_case(&id.value))
                                .map(|(pos, _)| pos);
                            pos.and_then(|pos| group_key.get(pos).and_then(|v| v.clone()))
                        }
                        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(parts)) => {
                            let name = parts.last().map(|i| i.value.clone()).unwrap_or_default();
                            let pos = group_by_cols.iter().enumerate()
                                .find(|(_, &c)| table.columns[c].name.eq_ignore_ascii_case(&name))
                                .map(|(pos, _)| pos);
                            pos.and_then(|pos| group_key.get(pos).and_then(|v| v.clone()))
                        }
                        _ => None,
                    }
                }).collect();
                // HAVING filter
                if let Some(having) = &sel.having {
                    // Evaluate HAVING against the aggregate result — build a synthetic row
                    // HAVING COUNT(*) > N: compare out_rows aggregate values
                    // Simple implementation: only support HAVING COUNT(*) > N / = N
                    // Build alias map from projection for HAVING alias resolution
                    let mut alias_map: std::collections::HashMap<String, Expr> = std::collections::HashMap::new();
                    for item in &sel.projection {
                        if let SelectItem::ExprWithAlias { expr, alias } = item {
                            alias_map.insert(alias.value.to_uppercase(), expr.clone());
                        }
                    }
                    let ok = eval_having_agg(having, &rows, &table.columns, &alias_map);
                    if !ok { return None; }
                }
                Some(row_vals)
            }).collect();
            return QueryResult::rows(out_cols, out_rows);
        }

        // ── Expression projection fast-check ────────────────────────────────
        // If any item is not a plain col-ref, evaluate all items via eval_row_expr.
        let is_plain_col = |p: &SelectItem| matches!(
            p,
            SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..)
            | SelectItem::UnnamedExpr(Expr::Identifier(_))
            | SelectItem::UnnamedExpr(Expr::CompoundIdentifier(_))
            | SelectItem::ExprWithAlias { expr: Expr::Identifier(_), .. }
            | SelectItem::ExprWithAlias { expr: Expr::CompoundIdentifier(_), .. }
        );
        let has_expr_projection = !sel.projection.iter().all(is_plain_col);
        if has_expr_projection {
            // Build list of (output_name, expr_to_evaluate) — wildcards expand to all columns
            let expr_proj: Vec<(String, Expr)> = if sel.projection.iter().any(|p| matches!(p, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..))) {
                table.columns.iter().map(|c| (c.name.clone(), Expr::Identifier(sqlparser::ast::Ident::new(c.name.clone())))).collect()
            } else {
                sel.projection.iter().map(|p| match p {
                    SelectItem::UnnamedExpr(expr) => {
                        let name = match expr {
                            Expr::Identifier(id) => id.value.clone(),
                            Expr::CompoundIdentifier(parts) => parts.last().map(|i| i.value.clone()).unwrap_or_else(|| expr.to_string()),
                            _ => expr.to_string(),
                        };
                        (name, expr.clone())
                    }
                    SelectItem::ExprWithAlias { expr, alias } => (alias.value.clone(), expr.clone()),
                    _ => ("?".to_owned(), Expr::Identifier(sqlparser::ast::Ident::new("__null__"))),
                }).collect()
            };
            let col_names: Vec<String> = expr_proj.iter().map(|(n, _)| n.clone()).collect();
            let mut result_rows: Vec<Vec<Option<String>>> = table.rows.iter()
                .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &table.columns, w)))
                .map(|row| {
                    expr_proj.iter().map(|(_, e)| eval_row_expr(row, &table.columns, e).to_display()).collect()
                })
                .collect();
            // ORDER BY
            if let Some(ob) = &query.order_by {
                if let sqlparser::ast::OrderByKind::Expressions(exprs) = &ob.kind {
                    for order_expr in exprs.iter().rev() {
                        let col_name = order_expr.expr.to_string();
                        if let Some(pidx) = col_names.iter().position(|n| n.eq_ignore_ascii_case(&col_name)) {
                            let asc = order_expr.options.asc.unwrap_or(true);
                            result_rows.sort_by(|a, b| {
                                let av = a.get(pidx).and_then(|x| x.as_deref());
                                let bv = b.get(pidx).and_then(|x| x.as_deref());
                                let ord = match (av, bv) {
                                    (Some(x), Some(y)) => match (x.parse::<i64>(), y.parse::<i64>()) {
                                        (Ok(xi), Ok(yi)) => xi.cmp(&yi), _ => x.cmp(y),
                                    },
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
            let offset = query.offset.as_ref().and_then(|o| {
                if let Expr::Value(vs) = &o.value {
                    if let sqlparser::ast::Value::Number(n, _) = &vs.value { n.parse::<usize>().ok() }
                    else { None }
                } else { None }
            }).unwrap_or(0);
            if offset > 0 { result_rows = result_rows.into_iter().skip(offset).collect(); }
            if let Some(lim) = &query.limit {
                if let Expr::Value(vs) = lim {
                    if let sqlparser::ast::Value::Number(n, _) = &vs.value {
                        if let Ok(n) = n.parse::<usize>() { result_rows.truncate(n); }
                    }
                }
            }
            return QueryResult::rows(col_names, result_rows);
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

        // Fast path: PK equality (O(1) lookup via HashMap index)
        if let (Some(pk_idx), Some(ref where_expr)) = (table.pk_col_idx, &sel.selection) {
            let pk_col_name = &table.columns[pk_idx].name.clone();
            if let Some(pk_val) = extract_pk_eq(pk_col_name, where_expr) {
                let result_rows: Vec<Vec<Option<String>>> =
                    if let Some(&ri) = table.pk_index.get(&pk_val) {
                        if ri < table.rows.len() {
                            let row = &table.rows[ri];
                            vec![proj_cols.iter().map(|(_, idx)| row.get(*idx).and_then(|v| v.to_display())).collect()]
                        } else { vec![] }
                    } else { vec![] };
                return QueryResult::rows(col_names, result_rows);
            }
        }

        // Fast path: SIMD column scan for int WHERE (AVX2 4-wide i64 comparison)
        let simd_indices: Option<Vec<usize>> =
            if let Some(ref where_expr) = sel.selection {
                try_simd_scan(&table, where_expr)
            } else { None };

        // ValueRows fast path: no ORDER BY or LIMIT → return Values directly.
        // Protocol layer encodes Int as ASCII on stack — zero heap allocation per row.
        let needs_postprocess = query.order_by.is_some()
            || query.limit.is_some()
            || query.offset.is_some();
        if !needs_postprocess {
            let value_rows: Vec<Vec<Value>> = if let Some(ref idxs) = simd_indices {
                idxs.iter()
                    .filter_map(|&ri| table.rows.get(ri))
                    .map(|row| proj_cols.iter()
                        .map(|(_, idx)| row.get(*idx).cloned().unwrap_or(Value::Null))
                        .collect())
                    .collect()
            } else {
                table.rows.iter()
                    .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &table.columns, w)))
                    .map(|row| proj_cols.iter()
                        .map(|(_, idx)| row.get(*idx).cloned().unwrap_or(Value::Null))
                        .collect())
                    .collect()
            };
            return QueryResult::value_rows(col_names, value_rows);
        }

        // Fallback String path (ORDER BY / LIMIT need comparable String values)
        // Collect source row references first so ORDER BY can access non-projected columns
        let mut src_rows: Vec<&Row> = if let Some(ref idxs) = simd_indices {
            idxs.iter().filter_map(|&ri| table.rows.get(ri)).collect()
        } else {
            table.rows.iter()
                .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where(r, &table.columns, w)))
                .collect()
        };

        // ORDER BY: sort source rows before projection so non-projected columns are accessible
        if let Some(ob) = &query.order_by {
            if let sqlparser::ast::OrderByKind::Expressions(exprs) = &ob.kind {
                for order_expr in exprs.iter().rev() {
                    let col_name = match &order_expr.expr {
                        Expr::Identifier(id) => id.value.clone(),
                        Expr::CompoundIdentifier(parts) =>
                            parts.last().map(|i| i.value.clone()).unwrap_or_default(),
                        other => other.to_string(),
                    };
                    if let Some(idx) = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name)) {
                        let asc = order_expr.options.asc.unwrap_or(true);
                        src_rows.sort_by(|a, b| {
                            let av = a.get(idx).and_then(|v| v.to_display()).unwrap_or_default();
                            let bv = b.get(idx).and_then(|v| v.to_display()).unwrap_or_default();
                            let ord = match (av.parse::<i64>(), bv.parse::<i64>()) {
                                (Ok(xi), Ok(yi)) => xi.cmp(&yi),
                                _ => av.cmp(&bv),
                            };
                            if asc { ord } else { ord.reverse() }
                        });
                    }
                }
            }
        }

        let mut result_rows: Vec<Vec<Option<String>>> = src_rows.iter()
            .map(|row| proj_cols.iter().map(|(_, idx)| row.get(*idx).and_then(|v| v.to_display())).collect())
            .collect();

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
        // DISTINCT deduplication
        let result_rows = if matches!(sel.distinct, Some(sqlparser::ast::Distinct::Distinct)) {
            let mut seen = std::collections::HashSet::new();
            result_rows.into_iter().filter(|r| seen.insert(r.clone())).collect()
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
        // PK fast path for UPDATE WHERE pk = literal
        let pk_eq: Option<(usize, String)> = if let (Some(pk_idx), Some(w)) = (table.pk_col_idx, selection) {
            let pk_name = table.columns[pk_idx].name.clone();
            extract_pk_eq(&pk_name, w).map(|v| (pk_idx, v))
        } else { None };

        if let Some((_, ref pk_val)) = pk_eq {
            if let Some(&ri) = table.pk_index.get(pk_val.as_str()) {
                if ri < table.rows.len() {
                    let row = &mut table.rows[ri];
                    for asgn in &assignments {
                        let col_name = asgn.target.to_string();
                        if let Some(idx) = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name)) {
                            let new_val = expr_to_value(asgn.value.clone());
                            // Keep col_int_data in sync
                            if let (Some(ref mut store), Value::Int(n)) = (table.col_int_data.get_mut(idx).and_then(|x| x.as_mut()), &new_val) {
                                if ri < store.len() { store[ri] = *n; }
                            }
                            // Keep col_str_data in sync
                            if let (Some(ref mut store), Value::Text(s)) = (table.col_str_data.get_mut(idx).and_then(|x| x.as_mut()), &new_val) {
                                if ri < store.len() { store[ri] = s.clone(); }
                            }
                            row[idx] = new_val;
                        }
                    }
                    affected = 1;
                }
            }
        } else {
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
        // PK fast path for DELETE WHERE pk = literal (O(1) swap_remove)
        let pk_eq_del: Option<String> = if let (Some(pk_idx), Some(w)) = (table.pk_col_idx, selection) {
            let pk_name = table.columns[pk_idx].name.clone();
            extract_pk_eq(&pk_name, w)
        } else { None };

        if let Some(ref pk_val) = pk_eq_del {
            if let Some(ri) = table.pk_index.remove(pk_val.as_str()) {
                if ri < table.rows.len() {
                    let last_idx = table.rows.len() - 1;
                    if ri != last_idx {
                        // Update pk_index for the row that will be swapped in
                        let moved_pk = row_pk_key(&table.rows[last_idx], table.pk_col_idx.unwrap());
                        table.pk_index.insert(moved_pk, ri);
                    }
                    table.rows.swap_remove(ri);
                    // Keep col_int_data in sync
                    for store in table.col_int_data.iter_mut().flatten() {
                        if ri < store.len() { store.swap_remove(ri); }
                    }
                    // Keep col_str_data in sync
                    for store in table.col_str_data.iter_mut().flatten() {
                        if ri < store.len() { store.swap_remove(ri); }
                    }
                }
            }
        } else {
            table.rows.retain(|row| {
                selection.map_or(false, |w| !eval_where(row, &table.columns, w))
            });
            // Rebuild pk_index after bulk delete (pk_index is only fast-path, not always correct after retain)
            if table.pk_col_idx.is_some() {
                table.pk_index.clear();
                let pk_i = table.pk_col_idx.unwrap();
                for (ri, row) in table.rows.iter().enumerate() {
                    table.pk_index.insert(row_pk_key(row, pk_i), ri);
                }
            }
            // Rebuild col_int_data and col_str_data after bulk delete
            for (ci, store) in table.col_int_data.iter_mut().enumerate() {
                if let Some(ref mut v) = store {
                    *v = table.rows.iter().map(|r| match r.get(ci) { Some(Value::Int(n)) => *n, _ => 0 }).collect();
                }
            }
            for (ci, store) in table.col_str_data.iter_mut().enumerate() {
                if let Some(ref mut v) = store {
                    *v = table.rows.iter().map(|r| match r.get(ci) { Some(Value::Text(s)) => s.clone(), _ => String::new() }).collect();
                }
            }
        }
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
                let _ = self.execute(&stmt, &current_db, "root");
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
                let qualified: String = parts.iter().map(|p| p.value.as_str()).collect::<Vec<_>>().join(".");
                cols.iter().position(|c| c.name.eq_ignore_ascii_case(&qualified))
                    .or_else(|| cols.iter().position(|c| c.name.eq_ignore_ascii_case(&last.value)))
                    .and_then(|idx| row.get(idx).cloned())
                    .unwrap_or(Value::Null)
            } else { Value::Null }
        }
        Expr::Nested(inner) => eval_row_expr(row, cols, inner),
        Expr::UnaryOp { op, expr: inner } => {
            let v = eval_row_expr(row, cols, inner);
            match op {
                UnaryOperator::Minus => match v {
                    Value::Int(i) => Value::Int(-i),
                    Value::Float(f) => Value::Float(-f),
                    _ => Value::Null,
                },
                UnaryOperator::Plus => v,
                _ => Value::Null,
            }
        }
        Expr::BinaryOp { left, op, right } => {
            use BinaryOperator::*;
            match op {
                Plus | Minus | Multiply | Divide | Modulo => {
                    let l = eval_row_expr(row, cols, left);
                    let r = eval_row_expr(row, cols, right);
                    match (l, r) {
                        (Value::Int(a), Value::Int(b)) => match op {
                            Plus     => Value::Int(a.wrapping_add(b)),
                            Minus    => Value::Int(a.wrapping_sub(b)),
                            Multiply => Value::Int(a.wrapping_mul(b)),
                            Divide   => if b != 0 { Value::Int(a / b) } else { Value::Null },
                            Modulo   => if b != 0 { Value::Int(a % b) } else { Value::Null },
                            _ => unreachable!(),
                        },
                        (Value::Float(a), Value::Float(b)) => match op {
                            Plus     => Value::Float(a + b),
                            Minus    => Value::Float(a - b),
                            Multiply => Value::Float(a * b),
                            Divide   => if b != 0.0 { Value::Float(a / b) } else { Value::Null },
                            Modulo   => Value::Float(a % b),
                            _ => unreachable!(),
                        },
                        (Value::Int(a), Value::Float(b)) => {
                            let a = a as f64;
                            match op {
                                Plus  => Value::Float(a + b), Minus => Value::Float(a - b),
                                Multiply => Value::Float(a * b),
                                Divide => if b != 0.0 { Value::Float(a / b) } else { Value::Null },
                                Modulo => Value::Float(a % b), _ => unreachable!(),
                            }
                        },
                        (Value::Float(a), Value::Int(b)) => {
                            let b = b as f64;
                            match op {
                                Plus  => Value::Float(a + b), Minus => Value::Float(a - b),
                                Multiply => Value::Float(a * b),
                                Divide => if b != 0.0 { Value::Float(a / b) } else { Value::Null },
                                Modulo => Value::Float(a % b), _ => unreachable!(),
                            }
                        },
                        (Value::Text(a), Value::Text(b)) if matches!(op, Plus) => Value::Text(a + &b),
                        _ => Value::Null,
                    }
                }
                _ => Value::Null,
            }
        }
        Expr::Cast { expr: inner, data_type, .. } => {
            let v = eval_row_expr(row, cols, inner);
            use sqlparser::ast::DataType;
            match data_type {
                DataType::Int(_) | DataType::Integer(_) | DataType::SmallInt(_) | DataType::TinyInt(_) | DataType::BigInt(_) => match v {
                    Value::Int(i) => Value::Int(i),
                    Value::Float(f) => Value::Int(f as i64),
                    Value::Text(s) => s.trim().parse::<i64>().map(Value::Int).unwrap_or(Value::Null),
                    _ => Value::Null,
                },
                DataType::Varchar(_) | DataType::Text | DataType::Char(_) => match v {
                    Value::Text(s) => Value::Text(s),
                    Value::Int(i) => Value::Text(i.to_string()),
                    Value::Float(f) => Value::Text(f.to_string()),
                    _ => Value::Null,
                },
                DataType::Float(_) | DataType::Real | DataType::Double(_) | DataType::DoublePrecision => match v {
                    Value::Float(f) => Value::Float(f),
                    Value::Int(i) => Value::Float(i as f64),
                    Value::Text(s) => s.trim().parse::<f64>().map(Value::Float).unwrap_or(Value::Null),
                    _ => Value::Null,
                },
                _ => v,
            }
        }
        Expr::Function(f) => {
            let fname = f.name.to_string().to_uppercase();
            let args: Vec<Value> = match &f.args {
                sqlparser::ast::FunctionArguments::List(list) => {
                    list.args.iter().map(|a| match a {
                        sqlparser::ast::FunctionArg::Unnamed(fae)
                        | sqlparser::ast::FunctionArg::Named { arg: fae, .. }
                        | sqlparser::ast::FunctionArg::ExprNamed { arg: fae, .. } => match fae {
                            sqlparser::ast::FunctionArgExpr::Expr(e) => eval_row_expr(row, cols, e),
                            _ => Value::Null,
                        },
                    }).collect()
                }
                _ => vec![],
            };
            match fname.as_str() {
                "UPPER" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Text(s.to_uppercase())).unwrap_or(Value::Null),
                "LOWER" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Text(s.to_lowercase())).unwrap_or(Value::Null),
                "LENGTH" | "CHAR_LENGTH" | "CHARACTER_LENGTH" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Int(s.chars().count() as i64)).unwrap_or(Value::Null),
                "TRIM" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Text(s.trim().to_owned())).unwrap_or(Value::Null),
                "LTRIM" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Text(s.trim_start().to_owned())).unwrap_or(Value::Null),
                "RTRIM" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Text(s.trim_end().to_owned())).unwrap_or(Value::Null),
                "REVERSE" => args.into_iter().next().and_then(|v| v.into_text()).map(|s| Value::Text(s.chars().rev().collect())).unwrap_or(Value::Null),
                "HEX" => args.into_iter().next().map(|v| match v {
                    Value::Int(i) => Value::Text(format!("{:X}", i)),
                    Value::Text(s) => Value::Text(s.bytes().map(|b| format!("{:02X}", b)).collect::<String>()),
                    _ => Value::Null,
                }).unwrap_or(Value::Null),
                "CONCAT" => {
                    let parts: Vec<String> = args.into_iter().filter_map(|v| v.into_text()).collect();
                    Value::Text(parts.join(""))
                }
                "CONCAT_WS" => {
                    let mut it = args.into_iter();
                    let sep = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let parts: Vec<String> = it.filter_map(|v| v.into_text()).collect();
                    Value::Text(parts.join(&sep))
                }
                "LEFT" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let n = it.next().and_then(|v| v.into_int()).unwrap_or(0).max(0) as usize;
                    Value::Text(s.chars().take(n).collect())
                }
                "RIGHT" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let n = it.next().and_then(|v| v.into_int()).unwrap_or(0).max(0) as usize;
                    let ch: Vec<char> = s.chars().collect();
                    Value::Text(ch[ch.len().saturating_sub(n)..].iter().collect())
                }
                "SUBSTRING" | "SUBSTR" | "MID" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let start = it.next().and_then(|v| v.into_int()).unwrap_or(1).max(1) as usize - 1;
                    let len_opt = it.next().and_then(|v| v.into_int()).map(|n| n.max(0) as usize);
                    let chars: Vec<char> = s.chars().collect();
                    let slice = &chars[start.min(chars.len())..];
                    let result: String = match len_opt {
                        Some(n) => slice.iter().take(n).collect(),
                        None => slice.iter().collect(),
                    };
                    Value::Text(result)
                }
                "REPLACE" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let from = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let to = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    Value::Text(s.replace(from.as_str(), to.as_str()))
                }
                "REPEAT" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let n = it.next().and_then(|v| v.into_int()).unwrap_or(0).max(0) as usize;
                    Value::Text(s.repeat(n))
                }
                "LPAD" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let len = it.next().and_then(|v| v.into_int()).unwrap_or(0).max(0) as usize;
                    let pad = it.next().and_then(|v| v.into_text()).unwrap_or_else(|| " ".to_owned());
                    let chars: Vec<char> = s.chars().collect();
                    if chars.len() >= len { return Value::Text(chars.into_iter().collect()); }
                    let needed = len - chars.len();
                    let pad_chars: Vec<char> = pad.chars().collect();
                    if pad_chars.is_empty() { return Value::Text(s); }
                    let prefix: String = pad_chars.iter().cycle().take(needed).collect();
                    Value::Text(prefix + &s)
                }
                "RPAD" => {
                    let mut it = args.into_iter();
                    let s = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let len = it.next().and_then(|v| v.into_int()).unwrap_or(0).max(0) as usize;
                    let pad = it.next().and_then(|v| v.into_text()).unwrap_or_else(|| " ".to_owned());
                    let chars: Vec<char> = s.chars().collect();
                    if chars.len() >= len { return Value::Text(s); }
                    let needed = len - chars.len();
                    let pad_chars: Vec<char> = pad.chars().collect();
                    if pad_chars.is_empty() { return Value::Text(s); }
                    let suffix: String = pad_chars.iter().cycle().take(needed).collect();
                    Value::Text(s + &suffix)
                }
                "ABS" => args.into_iter().next().map(|v| match v {
                    Value::Int(i) => Value::Int(i.abs()),
                    Value::Float(f) => Value::Float(f.abs()),
                    _ => Value::Null,
                }).unwrap_or(Value::Null),
                "CEIL" | "CEILING" => args.into_iter().next().map(|v| match v {
                    Value::Float(f) => Value::Int(f.ceil() as i64),
                    Value::Int(i) => Value::Int(i),
                    _ => Value::Null,
                }).unwrap_or(Value::Null),
                "FLOOR" => args.into_iter().next().map(|v| match v {
                    Value::Float(f) => Value::Int(f.floor() as i64),
                    Value::Int(i) => Value::Int(i),
                    _ => Value::Null,
                }).unwrap_or(Value::Null),
                "ROUND" => {
                    let mut it = args.into_iter();
                    let v = it.next().unwrap_or(Value::Null);
                    let dec = it.next().and_then(|v| v.into_int()).unwrap_or(0);
                    match v {
                        Value::Float(f) => { let m = 10f64.powi(dec as i32); Value::Float((f * m).round() / m) }
                        Value::Int(i) => Value::Int(i),
                        _ => Value::Null,
                    }
                }
                "MOD" => {
                    let mut it = args.into_iter();
                    match (it.next().unwrap_or(Value::Null), it.next().unwrap_or(Value::Null)) {
                        (Value::Int(a), Value::Int(b)) if b != 0 => Value::Int(a % b),
                        (Value::Float(a), Value::Float(b)) if b != 0.0 => Value::Float(a % b),
                        _ => Value::Null,
                    }
                }
                "POW" | "POWER" => {
                    let mut it = args.into_iter();
                    match (it.next().unwrap_or(Value::Null), it.next().unwrap_or(Value::Null)) {
                        (Value::Int(b), Value::Int(e)) if e >= 0 => Value::Int(b.pow(e as u32)),
                        (Value::Float(b), Value::Float(e)) => Value::Float(b.powf(e)),
                        (Value::Int(b), Value::Float(e)) => Value::Float((b as f64).powf(e)),
                        (Value::Float(b), Value::Int(e)) => Value::Float(b.powi(e as i32)),
                        _ => Value::Null,
                    }
                }
                "SQRT" => args.into_iter().next().map(|v| match v {
                    Value::Float(f) => Value::Float(f.sqrt()),
                    Value::Int(i) => Value::Float((i as f64).sqrt()),
                    _ => Value::Null,
                }).unwrap_or(Value::Null),
                "NOW" | "CURRENT_TIMESTAMP" | "SYSDATE" => {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let s = ts % 60; let m = (ts / 60) % 60; let h = (ts / 3600) % 24;
                    let (y, mo, d) = days_to_ymd(ts / 86400);
                    Value::Text(format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, mo, d, h, m, s))
                }
                "CURDATE" | "CURRENT_DATE" => {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let (y, mo, d) = days_to_ymd(ts / 86400);
                    Value::Text(format!("{:04}-{:02}-{:02}", y, mo, d))
                }
                "CURTIME" | "CURRENT_TIME" => {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let s = ts % 60; let m = (ts / 60) % 60; let h = (ts / 3600) % 24;
                    Value::Text(format!("{:02}:{:02}:{:02}", h, m, s))
                }
                "UNIX_TIMESTAMP" => {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    Value::Int(ts as i64)
                }
                "YEAR" => args.into_iter().next().and_then(|v| v.into_text()).and_then(|s| {
                    s.split('-').next().and_then(|y| y.parse::<i64>().ok()).map(Value::Int)
                }).unwrap_or(Value::Null),
                "MONTH" => args.into_iter().next().and_then(|v| v.into_text()).and_then(|s| {
                    s.splitn(3, '-').nth(1).and_then(|m| m.parse::<i64>().ok()).map(Value::Int)
                }).unwrap_or(Value::Null),
                "DAY" | "DAYOFMONTH" => args.into_iter().next().and_then(|v| v.into_text()).and_then(|s| {
                    s.splitn(4, '-').nth(2).and_then(|d| d.split(' ').next()).and_then(|d| d.parse::<i64>().ok()).map(Value::Int)
                }).unwrap_or(Value::Null),
                "IF" => {
                    let mut it = args.into_iter();
                    let cond = it.next().unwrap_or(Value::Null);
                    let t = it.next().unwrap_or(Value::Null);
                    let f_val = it.next().unwrap_or(Value::Null);
                    let truthy = !matches!(&cond, Value::Int(0) | Value::Null);
                    if truthy { t } else { f_val }
                }
                "IFNULL" | "NVL" => {
                    let mut it = args.into_iter();
                    let v = it.next().unwrap_or(Value::Null);
                    let fallback = it.next().unwrap_or(Value::Null);
                    if matches!(v, Value::Null) { fallback } else { v }
                }
                "NULLIF" => {
                    let mut it = args.into_iter();
                    let a = it.next().unwrap_or(Value::Null);
                    let b = it.next().unwrap_or(Value::Null);
                    if values_eq(&a, &b) { Value::Null } else { a }
                }
                "COALESCE" => args.into_iter().find(|v| !matches!(v, Value::Null)).unwrap_or(Value::Null),
                "ISNULL" => {
                    let v = args.into_iter().next().unwrap_or(Value::Null);
                    Value::Int(if matches!(v, Value::Null) { 1 } else { 0 })
                }
                "GREATEST" => {
                    let vals: Vec<Value> = args.into_iter().filter(|v| !matches!(v, Value::Null)).collect();
                    vals.into_iter().max_by(|a, b| values_cmp(a, b)).unwrap_or(Value::Null)
                }
                "LEAST" => {
                    let vals: Vec<Value> = args.into_iter().filter(|v| !matches!(v, Value::Null)).collect();
                    vals.into_iter().min_by(|a, b| values_cmp(a, b)).unwrap_or(Value::Null)
                }
                "FIELD" => {
                    let mut it = args.into_iter();
                    let target = it.next().unwrap_or(Value::Null);
                    it.enumerate().find_map(|(i, v)| if values_eq(&target, &v) { Some(Value::Int((i + 1) as i64)) } else { None })
                        .unwrap_or(Value::Int(0))
                }
                "FIND_IN_SET" => {
                    let mut it = args.into_iter();
                    let needle = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let haystack = it.next().and_then(|v| v.into_text()).unwrap_or_default();
                    let pos = haystack.split(',').enumerate()
                        .find_map(|(i, s)| if s == needle { Some(i + 1) } else { None })
                        .unwrap_or(0);
                    Value::Int(pos as i64)
                }
                _ => Value::Null,
            }
        }
        Expr::Case { operand, conditions, else_result } => {
            let base = operand.as_ref().map(|e| eval_row_expr(row, cols, e));
            for cw in conditions.iter() {
                let matched = if let Some(ref b) = base {
                    let cv = eval_row_expr(row, cols, &cw.condition);
                    values_eq(b, &cv)
                } else {
                    eval_where(row, cols, &cw.condition)
                };
                if matched { return eval_row_expr(row, cols, &cw.result); }
            }
            else_result.as_ref().map(|e| eval_row_expr(row, cols, e)).unwrap_or(Value::Null)
        }
        _ => Value::Null,
    }
}

/// Days since Unix epoch → (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    let mut rem = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let yd = if leap { 366 } else { 365 };
        if rem < yd { break; }
        rem -= yd; y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [31u64, if leap {29} else {28}, 31,30,31,30,31,31,30,31,30,31];
    let mut mo = 1u64;
    for &md in &mdays { if rem < md { break; } rem -= md; mo += 1; }
    (y, mo, rem + 1)
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


fn eval_having_agg_val(expr: &Expr, rows: &[&Row], cols: &[Column], alias_map: &std::collections::HashMap<String, Expr>) -> Value {
    match expr {
        Expr::Function(f) => {
            let fname = f.name.to_string().to_uppercase();
            let col_arg = f.args.to_string().trim().trim_start_matches('(').trim_end_matches(')').trim().to_owned();
            match fname.as_str() {
                "COUNT" => Value::Int(rows.len() as i64),
                "SUM" => {
                    if let Some(ci) = cols.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg)) {
                        Value::Int(rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .sum::<i64>())
                    } else { Value::Null }
                }
                "AVG" => {
                    if let Some(ci) = cols.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg)) {
                        let nums: Vec<i64> = rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .collect();
                        if nums.is_empty() { Value::Null }
                        else { Value::Int(nums.iter().sum::<i64>() / nums.len() as i64) }
                    } else { Value::Null }
                }
                "MAX" => {
                    if let Some(ci) = cols.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg)) {
                        rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .max().map(Value::Int).unwrap_or(Value::Null)
                    } else { Value::Null }
                }
                "MIN" => {
                    if let Some(ci) = cols.iter().position(|c| c.name.eq_ignore_ascii_case(&col_arg)) {
                        rows.iter().filter_map(|r| r.get(ci))
                            .filter_map(|v| if let Value::Int(n) = v { Some(*n) } else { None })
                            .min().map(Value::Int).unwrap_or(Value::Null)
                    } else { Value::Null }
                }
                _ => Value::Null,
            }
        }
        Expr::Value(vs) => expr_to_value(Expr::Value(vs.clone())),
        Expr::Identifier(id) => {
            // Check alias map first (for HAVING with projected aliases)
            if let Some(aliased_expr) = alias_map.get(&id.value.to_uppercase()) {
                return eval_having_agg_val(aliased_expr, rows, cols, alias_map);
            }
            if let Some(ci) = cols.iter().position(|c| c.name.eq_ignore_ascii_case(&id.value)) {
                rows.first().and_then(|r| r.get(ci)).cloned().unwrap_or(Value::Null)
            } else { Value::Null }
        }
        _ => Value::Null,
    }
}

fn eval_having_agg(expr: &Expr, rows: &[&Row], cols: &[Column], alias_map: &std::collections::HashMap<String, Expr>) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            match op {
                BinaryOperator::And => eval_having_agg(left, rows, cols, alias_map) && eval_having_agg(right, rows, cols, alias_map),
                BinaryOperator::Or  => eval_having_agg(left, rows, cols, alias_map) || eval_having_agg(right, rows, cols, alias_map),
                op => {
                    let lv = eval_having_agg_val(left, rows, cols, alias_map);
                    let rv = eval_having_agg_val(right, rows, cols, alias_map);
                    match op {
                        BinaryOperator::Eq    => values_eq(&lv, &rv),
                        BinaryOperator::NotEq => !values_eq(&lv, &rv),
                        BinaryOperator::Gt    => values_cmp(&lv, &rv) == std::cmp::Ordering::Greater,
                        BinaryOperator::GtEq  => values_cmp(&lv, &rv) != std::cmp::Ordering::Less,
                        BinaryOperator::Lt    => values_cmp(&lv, &rv) == std::cmp::Ordering::Less,
                        BinaryOperator::LtEq  => values_cmp(&lv, &rv) != std::cmp::Ordering::Greater,
                        _ => true,
                    }
                }
            }
        }
        Expr::UnaryOp { op, expr } if matches!(op, UnaryOperator::Not) => !eval_having_agg(expr, rows, cols, alias_map),
        _ => true,
    }
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
    /// Zero-copy: Values encoded in protocol layer without String conversion.
    /// Int values → ASCII on stack buffer, Text → direct slice. No heap per row.
    ValueRows { columns: Vec<String>, rows: Vec<Vec<Value>> },
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
    pub fn value_rows(cols: Vec<String>, rows: Vec<Vec<Value>>) -> Self {
        Self::ValueRows { columns: cols, rows }
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

// ── User management helpers ────────────────────────────────────────────────

fn double_sha1(data: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
    let h1 = Sha1::digest(data);
    Sha1::digest(&h1).to_vec()
}

impl Engine {
    // ── CREATE USER 'name'@'%' IDENTIFIED BY 'password' ──────────────────

    pub fn exec_create_user(&self, sql: &str) -> QueryResult {
        // Parse: CREATE USER 'user'@'host' IDENTIFIED BY 'pass'
        //    or: CREATE USER 'user' IDENTIFIED BY 'pass'
        //    or: CREATE USER 'user' (no password)
        let rest = sql.trim_start_matches(|c: char| !c.is_whitespace()).trim();
        let rest = rest.trim_start_matches(|c: char| c.is_whitespace());
        // skip "USER" keyword
        let rest = if rest.to_uppercase().starts_with("USER") { &rest[4..].trim_start() } else { rest };

        // Extract username (with optional @host which we ignore)
        let (username, password) = parse_user_ident_with_password(rest);

        if username.is_empty() {
            return QueryResult::err(1064, "CREATE USER: cannot parse username");
        }
        if username == "root" {
            return QueryResult::err(1396, "Operation CREATE USER failed for 'root'@'%'");
        }

        let hash = double_sha1(password.as_bytes());
        let mut users = self.users.write().unwrap_or_else(|e| e.into_inner());
        if users.contains_key(&username) {
            return QueryResult::err(1396, &format!("Operation CREATE USER failed for '{username}'@'%'"));
        }
        users.insert(username.clone(), DbUser {
            password_sha1_sha1: hash,
            allowed_dbs: Some(std::collections::HashSet::new()), // no access by default
            can_write: false,
            is_root: false,
        });
        tracing::info!(user = %username, "CREATE USER");
        QueryResult::ok(0, 0)
    }

    // ── DROP USER ─────────────────────────────────────────────────────────

    pub fn exec_drop_user(&self, sql: &str) -> QueryResult {
        let rest = sql["DROP USER".len()..].trim().trim_matches('\'').trim_matches('`');
        let username = rest.split('@').next().unwrap_or(rest).trim_matches('\'').trim_matches('`').trim();
        if username == "root" {
            return QueryResult::err(1396, "Cannot drop root user");
        }
        let mut users = self.users.write().unwrap_or_else(|e| e.into_inner());
        if users.remove(username).is_none() {
            return QueryResult::err(1396, &format!("Operation DROP USER failed for '{username}'@'%'"));
        }
        tracing::info!(user = %username, "DROP USER");
        QueryResult::ok(0, 0)
    }

    // ── GRANT SELECT|INSERT|UPDATE|DELETE|ALL ON db.* TO 'user' ──────────

    pub fn exec_grant(&self, sql: &str) -> QueryResult {
        // GRANT <privs> ON <db>.* TO 'user'[@'host'] [IDENTIFIED BY 'pass']
        let upper = sql.to_uppercase();
        let to_pos = upper.find(" TO ").ok_or(()).unwrap_err();
        if let Some(to_pos) = upper.find(" TO ") {
            let privs_on = &sql[6..to_pos].trim(); // skip "GRANT "
            let rest = sql[to_pos + 4..].trim();

            // Extract user and optional password
            let (username, new_password) = parse_user_ident_with_password(rest);
            if username.is_empty() {
                return QueryResult::err(1064, "GRANT: cannot parse username");
            }

            // Parse db name from "ON db.* " or "ON *.*"
            let db_name = if let Some(on_pos) = privs_on.to_uppercase().find(" ON ") {
                let on_part = privs_on[on_pos + 4..].trim();
                let db = on_part.split('.').next().unwrap_or("*").trim().trim_matches('`').trim_matches('\'');
                if db == "*" { None } else { Some(db.to_owned()) }
            } else {
                None
            };

            let all_privs = privs_on.to_uppercase().contains("ALL");
            let can_write = all_privs
                || privs_on.to_uppercase().contains("INSERT")
                || privs_on.to_uppercase().contains("UPDATE")
                || privs_on.to_uppercase().contains("DELETE")
                || privs_on.to_uppercase().contains("CREATE")
                || privs_on.to_uppercase().contains("DROP");

            let mut users = self.users.write().unwrap_or_else(|e| e.into_inner());
            let user = users.entry(username.clone()).or_insert_with(|| {
                // Auto-create user if it doesn't exist (MySQL behaviour with IDENTIFIED BY)
                DbUser {
                    password_sha1_sha1: double_sha1(b""),
                    allowed_dbs: Some(std::collections::HashSet::new()),
                    can_write: false,
                    is_root: false,
                }
            });

            // Update password if IDENTIFIED BY clause present
            if !new_password.is_empty() {
                user.password_sha1_sha1 = double_sha1(new_password.as_bytes());
            }

            if all_privs && db_name.is_none() {
                // GRANT ALL ON *.* — global access
                user.allowed_dbs = None;
                user.can_write = true;
            } else if let Some(ref db) = db_name {
                if let Some(ref mut set) = user.allowed_dbs {
                    set.insert(db.clone());
                }
                if can_write { user.can_write = true; }
            }

            tracing::info!(user = %username, db = ?db_name, can_write, "GRANT");
            drop(users); // release lock before bump
            self.bump_write_gen();
            QueryResult::ok(0, 0)
        } else {
            QueryResult::err(1064, "GRANT: syntax error — missing TO")
        }
    }

    // ── REVOKE ────────────────────────────────────────────────────────────

    pub fn exec_revoke(&self, sql: &str) -> QueryResult {
        let upper = sql.to_uppercase();
        if let Some(from_pos) = upper.find(" FROM ") {
            let rest = sql[from_pos + 6..].trim();
            let username = rest.split('@').next().unwrap_or(rest)
                .trim_matches('\'').trim_matches('`').trim();
            let privs_on = &sql[7..from_pos].trim(); // skip "REVOKE "
            let db_name = if let Some(on_pos) = privs_on.to_uppercase().find(" ON ") {
                let on_part = privs_on[on_pos + 4..].trim();
                let db = on_part.split('.').next().unwrap_or("*").trim().trim_matches('`').trim_matches('\'');
                if db == "*" { None } else { Some(db.to_owned()) }
            } else {
                None
            };

            let mut users = self.users.write().unwrap_or_else(|e| e.into_inner());
            let user = match users.get_mut(username) {
                Some(u) => u,
                None => return QueryResult::err(1396, &format!("No such user '{username}'")),
            };
            if let Some(ref db) = db_name {
                if let Some(ref mut set) = user.allowed_dbs {
                    set.remove(db);
                }
            } else {
                // Revoke global — restrict to empty set
                user.allowed_dbs = Some(std::collections::HashSet::new());
                user.can_write = false;
            }
            tracing::info!(user = %username, db = ?db_name, "REVOKE");
            drop(users); // release lock before bump
            self.bump_write_gen();
            QueryResult::ok(0, 0)
        } else {
            QueryResult::err(1064, "REVOKE: syntax error — missing FROM")
        }
    }

    // ── SHOW GRANTS FOR 'user' ────────────────────────────────────────────

    pub fn exec_show_grants(&self, sql: &str) -> QueryResult {
        let for_user = if let Some(pos) = sql.to_uppercase().find(" FOR ") {
            sql[pos + 5..].trim().split('@').next()
                .unwrap_or("").trim_matches('\'').trim_matches('`').trim().to_owned()
        } else {
            String::new()
        };

        let users = self.users.read().unwrap_or_else(|e| e.into_inner());
        let user = match users.get(&for_user) {
            Some(u) => u,
            None => return QueryResult::err(1141, &format!("No such user '{for_user}'")),
        };

        let rows = if user.allowed_dbs.is_none() {
            // Global access
            let priv_str = if user.can_write { "ALL PRIVILEGES" } else { "SELECT" };
            vec![vec![Some(format!("GRANT {priv_str} ON *.* TO '{for_user}'@'%'"))]]
        } else {
            let set = user.allowed_dbs.as_ref().unwrap();
            if set.is_empty() {
                vec![vec![Some(format!("GRANT USAGE ON *.* TO '{for_user}'@'%'"))]]
            } else {
                let priv_str = if user.can_write { "ALL PRIVILEGES" } else { "SELECT" };
                set.iter().map(|db| {
                    vec![Some(format!("GRANT {priv_str} ON `{db}`.* TO '{for_user}'@'%'"))]
                }).collect()
            }
        };

        QueryResult::rows(vec![&format!("Grants for {for_user}@%")], rows)
    }

    // ── Auth helper — check credentials at connection time ────────────────

    /// Returns true if the given user is allowed to authenticate.
    /// The password check (native_password SHA1 XOR) is done in auth.rs;
    /// this method only checks whether the user exists and returns the
    /// stored SHA1(SHA1(password)) hash.
    pub fn lookup_user(&self, username: &str) -> Option<(Vec<u8>, bool)> {
        let users = self.users.read().unwrap_or_else(|e| e.into_inner());
        users.get(username).map(|u| (u.password_sha1_sha1.clone(), u.is_root))
    }

    /// Validate a webui login against the MySQL users table (double-SHA1 comparison).
    pub fn verify_webui_password(&self, username: &str, password: &str) -> bool {
        use sha1::{Digest, Sha1};
        let h1 = Sha1::digest(password.as_bytes());
        let computed = Sha1::digest(&h1).to_vec();
        let users = self.users.read().unwrap_or_else(|e| e.into_inner());
        if let Some(user) = users.get(username) {
            return bool::from(user.password_sha1_sha1.as_slice().ct_eq(&computed));
        }
        // Constant-time: compare with dummy to avoid user enumeration via timing
        let dummy = vec![0u8; computed.len()];
        let _ = bool::from(dummy.as_slice().ct_eq(&computed));
        false
    }

    /// Check if a user has access to a given database.
    pub fn user_can_access_db(&self, username: &str, db: &str) -> bool {
        let users = self.users.read().unwrap_or_else(|e| e.into_inner());
        match users.get(username) {
            None => false,
            Some(u) => {
                if u.is_root || u.allowed_dbs.is_none() { return true; }
                u.allowed_dbs.as_ref().map(|s| s.contains(db)).unwrap_or(false)
            }
        }
    }
}

impl Engine {
    fn exec_select_sysvar(&self, sql: &str) -> QueryResult {
        // Extract variable names from SELECT @@var1, @@var2 [AS alias]
        // Supports: @@max_allowed_packet, @@character_set_*, @@collation_*, etc.
        fn sysvar_value(name: &str) -> Option<String> {
            match name.to_lowercase().trim_start_matches('@').trim_start_matches("session.").trim_start_matches("global.") {
                "max_allowed_packet"          => Some("67108864".into()),
                "character_set_client"        => Some("utf8mb4".into()),
                "character_set_connection"    => Some("utf8mb4".into()),
                "character_set_results"       => Some("utf8mb4".into()),
                "character_set_server"        => Some("utf8mb4".into()),
                "collation_connection"        => Some("utf8mb4_general_ci".into()),
                "collation_server"            => Some("utf8mb4_general_ci".into()),
                "time_zone"                   => Some("UTC".into()),
                "sql_mode"                    => Some("STRICT_TRANS_TABLES".into()),
                "auto_increment_increment"    => Some("1".into()),
                "transaction_isolation"       => Some("REPEATABLE-READ".into()),
                "tx_isolation"                => Some("REPEATABLE-READ".into()),
                "lower_case_table_names"      => Some("0".into()),
                "version"                     => Some("8.0.32-RunAlexDB".into()),
                "version_comment"             => Some("RunAlexDB".into()),
                "wait_timeout"               => Some("28800".into()),
                "interactive_timeout"         => Some("28800".into()),
                "net_write_timeout"           => Some("60".into()),
                "net_read_timeout"            => Some("30".into()),
                "init_connect"                => Some("".into()),
                _                             => None,
            }
        }

        // Extract everything after SELECT
        let after_select = if let Some(pos) = sql.to_uppercase().find("SELECT ") {
            &sql[pos + 7..]
        } else { sql };

        // Split on comma, handle AS aliases
        let mut col_names = Vec::new();
        let mut row = Vec::new();
        for part in after_select.split(',') {
            let part = part.trim();
            let (var_part, alias) = if let Some(idx) = part.to_uppercase().find(" AS ") {
                let v = part[..idx].trim();
                let a = part[idx+4..].trim().trim_matches('`').trim_matches('\'');
                (v, a.to_owned())
            } else {
                (part, part.trim_matches('`').to_owned())
            };
            let val = sysvar_value(var_part.trim()).unwrap_or_else(|| var_part.trim().to_owned());
            col_names.push(alias);
            row.push(Some(val));
        }
        QueryResult::rows(col_names.iter().map(|s| s.as_str()).collect(), vec![row])
    }
}


// ── Parse helpers ─────────────────────────────────────────────────────────

/// Parse `'username'@'host' [IDENTIFIED BY 'password']`
/// Returns (username, password).
fn parse_user_ident_with_password(s: &str) -> (String, String) {
    let s = s.trim();
    // Extract quoted or bare username
    let (username, rest) = if s.starts_with('\'') {
        let end = s[1..].find('\'').map(|p| p + 1).unwrap_or(s.len() - 1);
        (s[1..end].to_owned(), &s[end + 1..])
    } else if s.starts_with('`') {
        let end = s[1..].find('`').map(|p| p + 1).unwrap_or(s.len() - 1);
        (s[1..end].to_owned(), &s[end + 1..])
    } else {
        let end = s.find(|c: char| c == '@' || c.is_whitespace()).unwrap_or(s.len());
        (s[..end].to_owned(), &s[end..])
    };

    // Skip @'host' if present
    let rest = rest.trim_start_matches(|c: char| c == '@' || c == '\'');
    let rest = if rest.starts_with('\'') {
        let end = rest[1..].find('\'').map(|p| p + 2).unwrap_or(rest.len());
        &rest[end..]
    } else {
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        &rest[end..]
    };

    // Look for IDENTIFIED BY 'password'
    let upper = rest.to_uppercase();
    let password = if let Some(pos) = upper.find("IDENTIFIED BY") {
        let pw_rest = rest[pos + 13..].trim();
        if pw_rest.starts_with('\'') {
            let end = pw_rest[1..].find('\'').unwrap_or(pw_rest.len() - 1);
            pw_rest[1..end + 1].to_owned()
        } else {
            pw_rest.split_whitespace().next().unwrap_or("").to_owned()
        }
    } else {
        String::new()
    };

    (username, password)
}

impl Engine {
    /// Execute a prepared statement SQL (with ? placeholders) using bound parameters.
    /// The SQL with ? is used as the cache key — parse happens only once per statement.
    pub fn execute_prepared(&self, sql: &str, params: &[Option<String>], current_db: &Option<String>, user_name: &str) -> QueryResult {
        let bound: Vec<Value> = params.iter().map(|p| match p {
            None => Value::Null,
            Some(s) => match s.parse::<i64>() {
                Ok(n) => Value::Int(n),
                Err(_) => match s.parse::<f64>() {
                    Ok(f) => Value::Float(f),
                    Err(_) => Value::Text(s.clone()),
                },
            },
        }).collect();

        let stmts = match parse_cached(sql) {
            Ok(s) => s,
            Err(e) => return QueryResult::err(1064, &e),
        };
        // ── Privilege check ──────────────────────────────────────────────────
        {
            let users = self.users.read().unwrap_or_else(|e| e.into_inner());
            if let Some(user) = users.get(user_name) {
                if let (Some(ref allowed), Some(ref db)) = (&user.allowed_dbs, current_db) {
                    if !allowed.contains(db) {
                        return QueryResult::err(1044, &format!(
                            "Access denied for user '{}' to database '{}'", user_name, db
                        ));
                    }
                }
                if !user.can_write {
                    let needs_write = stmts.iter().any(|s| matches!(s,
                        Statement::Insert(_)
                        | Statement::Update { .. }
                        | Statement::Delete(_)
                        | Statement::CreateTable(_)
                        | Statement::CreateDatabase { .. }
                        | Statement::Drop { .. }
                    ));
                    if needs_write {
                        return QueryResult::err(1142, "Command denied to user (no write privilege)");
                    }
                }
            }
        }
        let mut last = QueryResult::ok(0, 0);
        for stmt in stmts.iter() {
            last = self.exec_stmt_prepared(stmt.clone(), &bound, current_db);
        }
        last
    }

    fn exec_stmt_prepared(&self, stmt: Statement, bound: &[Value], current_db: &Option<String>) -> QueryResult {
        match stmt {
            Statement::Query(q) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.select_prepared(db_name, *q, bound)
            }
            Statement::Insert(insert) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.insert_prepared(db_name, &insert.table.to_string(), insert.source, bound)
            }
            Statement::Update { table, assignments, selection, .. } => {
                let db_name = current_db.as_deref().unwrap_or("test");
                self.update_prepared(db_name, &table.relation.to_string(), assignments, selection.as_ref(), bound)
            }
            Statement::Delete(del) => {
                let db_name = current_db.as_deref().unwrap_or("test");
                let table_name = match &del.from {
                    sqlparser::ast::FromTable::WithFromKeyword(t)
                    | sqlparser::ast::FromTable::WithoutKeyword(t) => {
                        t.first().map(|x| x.relation.to_string()).unwrap_or_default()
                    }
                };
                self.delete_prepared(db_name, &table_name, del.selection.as_ref(), bound)
            }
            other => self.exec_stmt(other, current_db),
        }
    }

    fn select_prepared(&self, db_name: &str, query: Query, bound: &[Value]) -> QueryResult {
        let SetExpr::Select(sel) = *query.body else {
            return QueryResult::err(1295, "Complex SELECT not supported");
        };
        if sel.from.is_empty() { return QueryResult::err(1295, "No FROM"); }

        let raw = sel.from[0].relation.to_string();
        let (sel_db, tname) = if let Some(d) = raw.find('.') {
            (raw[..d].trim_matches('`').to_owned(), raw[d+1..].trim_matches('`').to_owned())
        } else { (db_name.to_owned(), raw.trim_matches('`').to_owned()) };

        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&sel_db) else {
            return QueryResult::err(1049, &format!("Unknown database '{sel_db}'"));
        };
        let db = db_arc.read().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get(&tname) else {
            return QueryResult::err(1146, &format!("Table not found: {tname}"));
        };

        // Column projection
        let proj_cols: Vec<(String, usize)> =
            if sel.projection.iter().any(|p| matches!(p, SelectItem::Wildcard(_) | SelectItem::QualifiedWildcard(..))) {
                table.columns.iter().enumerate().map(|(i, c)| (c.name.clone(), i)).collect()
            } else {
                sel.projection.iter().filter_map(|p| {
                    let col_name = match p {
                        SelectItem::UnnamedExpr(Expr::Identifier(id)) => id.value.clone(),
                        SelectItem::UnnamedExpr(Expr::CompoundIdentifier(ps)) => ps.last()?.value.clone(),
                        _ => return None,
                    };
                    let idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name))?;
                    Some((col_name, idx))
                }).collect()
            };
        let col_names: Vec<String> = proj_cols.iter().map(|(n, _)| n.clone()).collect();

        // PK fast path: WHERE pk = ? (O(1) lookup)
        if let (Some(pk_idx), Some(ref where_expr)) = (table.pk_col_idx, &sel.selection) {
            let pk_col_name = &table.columns[pk_idx].name.clone();
            if let Some(param_pos) = extract_pk_eq_param(pk_col_name, where_expr, 0) {
                if let Some(pk_val) = bound.get(param_pos).map(|v| value_to_pk_str(v)) {
                    let result_rows: Vec<Vec<Option<String>>> =
                        if let Some(&ri) = table.pk_index.get(&pk_val) {
                            if ri < table.rows.len() {
                                let row = &table.rows[ri];
                                vec![proj_cols.iter().map(|(_, idx)| row.get(*idx).and_then(|v| v.to_display())).collect()]
                            } else { vec![] }
                        } else { vec![] };
                    return QueryResult::rows(col_names, result_rows);
                }
            }
        }

        // Aggregate fast path
        let is_agg = !sel.projection.is_empty() && sel.projection.iter().all(|p| {
            matches!(p, SelectItem::UnnamedExpr(Expr::Function(_)) | SelectItem::ExprWithAlias { expr: Expr::Function(_), .. })
        });
        if is_agg {
            // COUNT(*) with no WHERE = table.rows.len()
            let has_where = sel.selection.is_some();
            let filtered: Vec<&Row> = if has_where {
                table.rows.iter()
                    .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where_bound(r, &table.columns, w, bound)))
                    .collect()
            } else {
                table.rows.iter().collect()
            };
            let agg_cols: Vec<String> = sel.projection.iter().map(|p| p.to_string()).collect();
            let agg_vals: Vec<Option<String>> = sel.projection.iter().map(|p| {
                let func = match p {
                    SelectItem::UnnamedExpr(Expr::Function(f)) => f,
                    SelectItem::ExprWithAlias { expr: Expr::Function(f), .. } => f,
                    _ => return None,
                };
                match func.name.to_string().to_uppercase().as_str() {
                    "COUNT" => Some(filtered.len().to_string()),
                    _ => None,
                }
            }).collect();
            return QueryResult::rows(agg_cols, vec![agg_vals]);
        }

        // General filter
        let result_rows: Vec<Vec<Option<String>>> = table.rows.iter()
            .filter(|r| sel.selection.as_ref().map_or(true, |w| eval_where_bound(r, &table.columns, w, bound)))
            .map(|row| proj_cols.iter().map(|(_, idx)| row.get(*idx).and_then(|v| v.to_display())).collect())
            .collect();
        QueryResult::rows(col_names, result_rows)
    }

    fn insert_prepared(&self, db_name: &str, table_name: &str, source: Option<Box<Query>>, bound: &[Value]) -> QueryResult {
        let Some(source) = source else { return QueryResult::err(1064, "INSERT without VALUES"); };
        let SetExpr::Values(Values { rows, .. }) = *source.body else {
            return QueryResult::err(1064, "Only VALUES inserts supported");
        };
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else { (db_name.to_owned(), table_name.trim_matches('`').to_owned()) };

        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(&eff_table) else { return QueryResult::err(1146, "Table not found"); };

        let count = rows.len() as u64;
        let mut param_idx = 0usize;
        for row_exprs in rows {
            let row: Row = row_exprs.into_iter().map(|e| {
                if matches!(e, Expr::Value(ref vs) if vs.value.to_string() == "?") {
                    let v = bound.get(param_idx).cloned().unwrap_or(Value::Null);
                    param_idx += 1;
                    v
                } else {
                    expr_to_value(e)
                }
            }).collect();
            if let Some(pk_idx) = table.pk_col_idx {
                let pk_key = row_pk_key(&row, pk_idx);
                table.pk_index.insert(pk_key, table.rows.len());
            }
            for (ci, store) in table.col_int_data.iter_mut().enumerate() {
                if let Some(ref mut v) = store {
                    v.push(match row.get(ci) { Some(Value::Int(n)) => *n, _ => 0 });
                }
            }
            for (ci, store) in table.col_str_data.iter_mut().enumerate() {
                if let Some(ref mut v) = store {
                    v.push(match row.get(ci) { Some(Value::Text(s)) => s.clone(), _ => String::new() });
                }
            }
            table.rows.push(row);
        }
        QueryResult::ok(count, 0)
    }

    fn update_prepared(&self, db_name: &str, table_name: &str, assignments: Vec<Assignment>, selection: Option<&Expr>, bound: &[Value]) -> QueryResult {
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else { (db_name.to_owned(), table_name.trim_matches('`').to_owned()) };
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(&eff_table) else { return QueryResult::err(1146, "Table not found"); };

        // PK fast path for UPDATE WHERE pk = ?
        if let (Some(pk_idx), Some(w)) = (table.pk_col_idx, selection) {
            let pk_col_name = table.columns[pk_idx].name.clone();
            let asgn_param_count = assignments.iter()
                .filter(|a| matches!(a.value, Expr::Value(ref vs) if vs.value.to_string() == "?"))
                .count();
            if let Some(param_pos) = extract_pk_eq_param(&pk_col_name, w, asgn_param_count) {
                if let Some(pk_val) = bound.get(param_pos).map(|v| value_to_pk_str(v)) {
                    if let Some(&ri) = table.pk_index.get(&pk_val) {
                        if ri < table.rows.len() {
                            // Resolve assignment bound params
                            let mut asgn_param = 0usize;
                            for asgn in &assignments {
                                let col_name = asgn.target.to_string();
                                if let Some(idx) = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(&col_name)) {
                                    let new_val = if matches!(asgn.value, Expr::Value(ref vs) if vs.value.to_string() == "?") {
                                        let v = bound.get(asgn_param).cloned().unwrap_or(Value::Null);
                                        asgn_param += 1;
                                        v
                                    } else { expr_to_value(asgn.value.clone()) };
                                    if let (Some(store), Value::Int(n)) = (table.col_int_data.get_mut(idx).and_then(|x| x.as_mut()), &new_val) {
                                        if ri < store.len() { store[ri] = *n; }
                                    }
                                    if let (Some(store), Value::Text(s)) = (table.col_str_data.get_mut(idx).and_then(|x| x.as_mut()), &new_val) {
                                        if ri < store.len() { store[ri] = s.clone(); }
                                    }
                                    table.rows[ri][idx] = new_val;
                                }
                            }
                        }
                    }
                    return QueryResult::ok(1, 0);
                }
            }
        }
        // General path
        let mut affected = 0u64;
        for row in table.rows.iter_mut() {
            if selection.map_or(true, |w| eval_where_bound(row, &table.columns, w, bound)) {
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

    fn delete_prepared(&self, db_name: &str, table_name: &str, selection: Option<&Expr>, bound: &[Value]) -> QueryResult {
        let (eff_db, eff_table) = if let Some(dot) = table_name.find('.') {
            (table_name[..dot].trim_matches('`').to_owned(), table_name[dot+1..].trim_matches('`').to_owned())
        } else { (db_name.to_owned(), table_name.trim_matches('`').to_owned()) };
        let dbs = self.databases.read().unwrap_or_else(|e| e.into_inner());
        let Some(db_arc) = dbs.get(&eff_db) else { return QueryResult::err(1049, "Unknown database"); };
        let mut db = db_arc.write().unwrap_or_else(|e| e.into_inner());
        let Some(table) = db.tables.get_mut(&eff_table) else { return QueryResult::err(1146, "Table not found"); };
        let before = table.rows.len();
        table.rows.retain(|row| selection.map_or(false, |w| !eval_where_bound(row, &table.columns, w, bound)));
        // Rebuild pk_index after bulk delete — indices shift after retain()
        if table.pk_col_idx.is_some() {
            table.pk_index.clear();
            let pk_i = table.pk_col_idx.unwrap();
            for (ri, row) in table.rows.iter().enumerate() {
                table.pk_index.insert(row_pk_key(row, pk_i), ri);
            }
        }
        // Rebuild col_int_data and col_str_data to match the new row layout
        for (ci, store) in table.col_int_data.iter_mut().enumerate() {
            if let Some(ref mut v) = store {
                *v = table.rows.iter().map(|r| match r.get(ci) {
                    Some(crate::engine::Value::Int(n)) => *n,
                    _ => 0,
                }).collect();
            }
        }
        for (ci, store) in table.col_str_data.iter_mut().enumerate() {
            if let Some(ref mut v) = store {
                *v = table.rows.iter().map(|r| match r.get(ci) {
                    Some(crate::engine::Value::Text(s)) => s.clone(),
                    _ => String::new(),
                }).collect();
            }
        }
        QueryResult::ok((before - table.rows.len()) as u64, 0)
    }

} // impl Engine (prepared stmt methods)

// ── Helper functions for PK index and SIMD dispatch ──────────────────────

/// Extract the PK value as a canonical string for use in pk_index.
fn row_pk_key(row: &Row, pk_col_idx: usize) -> String {
    match row.get(pk_col_idx) {
        Some(Value::Int(n))  => n.to_string(),
        Some(Value::Text(s)) => s.clone(),
        Some(v) => v.to_display().unwrap_or_default(),
        None => String::new(),
    }
}

/// Detect `WHERE pk_col = literal` pattern and return the literal as a String.
/// Supports both `col = val` and `val = col` forms.
fn extract_pk_eq(pk_col_name: &str, expr: &Expr) -> Option<String> {
    let Expr::BinaryOp { left, op: BinaryOperator::Eq, right } = expr else { return None };
    // Identify which side is the column and which is the literal
    let (col_expr, val_expr) = {
        let left_is_col = matches!(left.as_ref(),
            Expr::Identifier(_) | Expr::CompoundIdentifier(_));
        if left_is_col { (left.as_ref(), right.as_ref()) }
        else            { (right.as_ref(), left.as_ref()) }
    };
    let col_name = match col_expr {
        Expr::Identifier(id) => id.value.as_str(),
        Expr::CompoundIdentifier(parts) => parts.last()?.value.as_str(),
        _ => return None,
    };
    if !col_name.eq_ignore_ascii_case(pk_col_name) { return None; }
    match val_expr {
        Expr::Value(vs) => match &vs.value {
            sqlparser::ast::Value::Number(n, _) => Some(n.clone()),
            sqlparser::ast::Value::SingleQuotedString(s) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Try to accelerate a WHERE clause using the SIMD column store.
/// Returns Some(matching_indices) if a SIMD path was applicable, None otherwise.
fn try_simd_scan(table: &Table, expr: &Expr) -> Option<Vec<usize>> {
    let Expr::BinaryOp { left, op, right } = expr else { return None };
    let col_name = match left.as_ref() {
        Expr::Identifier(id) => id.value.as_str(),
        Expr::CompoundIdentifier(parts) => parts.last()?.value.as_str(),
        _ => return None,
    };
    let col_idx = table.columns.iter().position(|c| c.name.eq_ignore_ascii_case(col_name))?;

    // Try integer SIMD path first
    if let Some(Some(int_store)) = table.col_int_data.get(col_idx) {
        let target: i64 = match right.as_ref() {
            Expr::Value(vs) => match &vs.value {
                sqlparser::ast::Value::Number(n, _) => n.parse().ok()?,
                _ => return None,
            },
            _ => return None,
        };
        return Some(match op {
            BinaryOperator::Eq => crate::simd_scan::scan_eq_i64(int_store, target),
            BinaryOperator::Gt => crate::simd_scan::scan_gt_i64(int_store, target),
            BinaryOperator::Lt => crate::simd_scan::scan_lt_i64(int_store, target),
            _ => return None,
        });
    }

    // Try string SIMD path for Eq only
    if *op == BinaryOperator::Eq {
        if let Some(Some(str_store)) = table.col_str_data.get(col_idx) {
            let target: &str = match right.as_ref() {
                Expr::Value(vs) => match &vs.value {
                    sqlparser::ast::Value::SingleQuotedString(s) => s.as_str(),
                    _ => return None,
                },
                _ => return None,
            };
            return Some(crate::simd_scan::scan_eq_str(str_store, target));
        }
    }

    None
}

/// Convert a bound Value to the string key used in pk_index.
fn value_to_pk_str(v: &Value) -> String {
    match v {
        Value::Int(n)   => n.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Text(s)  => s.clone(),
        Value::Null     => String::new(),
        Value::Bytes(_) => String::new(),
    }
}

/// Detect `WHERE pk_col = ?` pattern and return the bound parameter index.
fn extract_pk_eq_param(pk_col_name: &str, expr: &Expr, param_offset: usize) -> Option<usize> {
    let Expr::BinaryOp { left, op: BinaryOperator::Eq, right } = expr else { return None };
    let (col_expr, val_expr) = {
        let left_is_col = matches!(left.as_ref(), Expr::Identifier(_) | Expr::CompoundIdentifier(_));
        if left_is_col { (left.as_ref(), right.as_ref()) } else { (right.as_ref(), left.as_ref()) }
    };
    let col_name = match col_expr {
        Expr::Identifier(id) => id.value.as_str(),
        Expr::CompoundIdentifier(parts) => parts.last()?.value.as_str(),
        _ => return None,
    };
    if !col_name.eq_ignore_ascii_case(pk_col_name) { return None; }
    if matches!(val_expr, Expr::Value(vs) if vs.value.to_string() == "?") { Some(param_offset) } else { None }
}

/// Evaluate a WHERE clause with bound parameters (? slots resolved from `bound`).
fn eval_where_bound(row: &Row, cols: &[Column], expr: &Expr, bound: &[Value]) -> bool {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            match op {
                BinaryOperator::And => eval_where_bound(row, cols, left, bound) && eval_where_bound(row, cols, right, bound),
                BinaryOperator::Or  => eval_where_bound(row, cols, left, bound) || eval_where_bound(row, cols, right, bound),
                _ => {
                    let lv = resolve_expr_bound(row, cols, left, bound);
                    let rv = resolve_expr_bound(row, cols, right, bound);
                    match op {
                        BinaryOperator::Eq    => values_eq(&lv, &rv),
                        BinaryOperator::NotEq => !values_eq(&lv, &rv),
                        BinaryOperator::Lt    => values_cmp(&lv, &rv) == std::cmp::Ordering::Less,
                        BinaryOperator::LtEq  => values_cmp(&lv, &rv) != std::cmp::Ordering::Greater,
                        BinaryOperator::Gt    => values_cmp(&lv, &rv) == std::cmp::Ordering::Greater,
                        BinaryOperator::GtEq  => values_cmp(&lv, &rv) != std::cmp::Ordering::Less,
                        _ => true,
                    }
                }
            }
        }
        Expr::UnaryOp { op: UnaryOperator::Not, expr } => !eval_where_bound(row, cols, expr, bound),
        Expr::IsNull(e)    => matches!(resolve_expr_bound(row, cols, e, bound), Value::Null),
        Expr::IsNotNull(e) => !matches!(resolve_expr_bound(row, cols, e, bound), Value::Null),
        Expr::Nested(inner) => eval_where_bound(row, cols, inner, bound),
        other => eval_where(row, cols, other),
    }
}

fn resolve_expr_bound(row: &Row, cols: &[Column], expr: &Expr, bound: &[Value]) -> Value {
    if matches!(expr, Expr::Value(vs) if vs.value.to_string() == "?") {
        return bound.first().cloned().unwrap_or(Value::Null);
    }
    match expr {
        Expr::Identifier(id) => {
            if let Some(idx) = cols.iter().position(|c| c.name.eq_ignore_ascii_case(&id.value)) {
                row.get(idx).cloned().unwrap_or(Value::Null)
            } else { Value::Null }
        }
        Expr::Value(vs) => value_from_sqlparser(&vs.value),
        _ => Value::Null,
    }
}

fn value_from_sqlparser(v: &sqlparser::ast::Value) -> Value {
    match v {
        sqlparser::ast::Value::Number(n, _) => {
            if let Ok(i) = n.parse::<i64>() { Value::Int(i) }
            else if let Ok(f) = n.parse::<f64>() { Value::Float(f) }
            else { Value::Text(n.clone()) }
        }
        sqlparser::ast::Value::SingleQuotedString(s)
        | sqlparser::ast::Value::DoubleQuotedString(s) => Value::Text(s.clone()),
        sqlparser::ast::Value::Null => Value::Null,
        _ => Value::Null,
    }
}

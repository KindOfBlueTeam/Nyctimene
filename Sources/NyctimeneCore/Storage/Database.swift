import Foundation
import GRDB

public class AppDatabase {
    public static let shared = AppDatabase()

    public let dbQueue: DatabaseQueue

    public init() {
        let dbURL = SettingsStore.dbURL()
        try? FileManager.default.createDirectory(
            at: dbURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )

        var config = Configuration()
        config.prepareDatabase { db in
            // WAL mode allows concurrent reads from both processes
            try db.execute(sql: "PRAGMA journal_mode = WAL")
            try db.execute(sql: "PRAGMA foreign_keys = ON")
        }

        dbQueue = try! DatabaseQueue(path: dbURL.path, configuration: config)
        try! runMigrations()
    }

    private func runMigrations() throws {
        var migrator = DatabaseMigrator()

        migrator.registerMigration("v1_initial_schema") { db in
            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER NOT NULL
                )
            """)
            let count = try Int.fetchOne(db, sql: "SELECT COUNT(*) FROM schema_version") ?? 0
            if count == 0 {
                try db.execute(sql: "INSERT INTO schema_version VALUES (1)")
            }

            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS domain_lists (
                    domain          TEXT NOT NULL,
                    list_type       TEXT NOT NULL,
                    added_at        DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reason          TEXT,
                    vt_score        INTEGER,
                    vt_report_url   TEXT,
                    PRIMARY KEY (domain, list_type)
                )
            """)

            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS vt_cache (
                    domain          TEXT PRIMARY KEY,
                    vt_score        INTEGER NOT NULL,
                    vt_report_url   TEXT,
                    cached_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ttl_hours       INTEGER DEFAULT 24
                )
            """)

            try db.execute(sql: """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
                    domain      TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    reason      TEXT,
                    vt_score    INTEGER
                )
            """)
        }

        try migrator.migrate(dbQueue)
    }
}

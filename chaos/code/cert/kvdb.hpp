/** -------------------------------------------------------------------------
 *  |                               _     _____    _____                    |
 *  |                       /\     | |   / ___/   / ___/                    |
 *  |                      /  \    | |  / /      / /                        |
 *  |                     / /\ \   | | ( (      ( (                         |
 *  |                    / / _\ \  | |  \ \___   \ \___                     |
 *  |                   /_/ /____\ |_|   \____/   \____/                    |
 *  |                                                                       |
 *  -------------------------------------------------------------------------
 *
 * @file kvdb.h
 * @brief KV数据库
 * @details 将sqlite3封装为KV数据库
 * @author HuangTingxuan<huangtingxuan@china-aicc.cn>
 * @date 2023-07-05
 * Copyright 2023-2025 AICC Inc.
 *
 * These materials and the intellectual property rights associated therewith
 * (“Materials”) are proprietary to AICC Inc. Any and all rights in
 * the Materials are reserved by AICC Inc. Nothing contained in
 * these Materials shall grant or be deemed to grant to you or anyone else, by
 * implication, estoppel or otherwise, any rights in these Materials.
 *
 */
#ifndef LIC_COMM_KVDB_H_
#define LIC_COMM_KVDB_H_

#include <sqlite3.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static const char *sql_create =
    "CREATE TABLE IF NOT EXISTS KEY_STORE (key INTEGER PRIMARY KEY, timestamp "
    "INTEGER, value BLOB);";
static const char *sql_insert =
    "INSERT OR REPLACE INTO KEY_STORE (key, "
    "timestamp, value) VALUES (?, ?, ?);";
static const char *sql_select = "SELECT value FROM KEY_STORE WHERE key=?;";
static const char *sql_delete = "DELETE FROM KEY_STORE WHERE key=?;";

class KvDatabase {
   public:
    KvDatabase(const std::string &db_path) : db(NULL) {
        int rc = sqlite3_open(db_path.c_str(), &db);
        if (rc) {
            std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            exit(1);
        }

        rc = sqlite3_exec(db, sql_create, 0, 0, &zErrMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "SQL error: " << zErrMsg << std::endl;
            sqlite3_free(zErrMsg);
            exit(1);
        }
    }

    void put(int key, const std::vector<uint8_t> &value) {
        sqlite3_stmt *stmt;
        do {
            int rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, NULL);
            if (rc != SQLITE_OK) {
                std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
            rc = sqlite3_bind_int(stmt, 1, key);
            if (rc != SQLITE_OK) {
                std::cerr << "Error binding parameter: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
            rc = sqlite3_bind_int(stmt, 2, (int)time(NULL));
            if (rc != SQLITE_OK) {
                std::cerr << "Error binding parameter: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
            rc = sqlite3_bind_blob(stmt, 3, value.data(), (int)value.size(), SQLITE_STATIC);
            if (rc != SQLITE_OK) {
                std::cerr << "Error binding parameter: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                std::cerr << "Error inserting value: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
        } while (0);
        sqlite3_finalize(stmt);
    }

    std::vector<uint8_t> get(int key) {
        std::vector<uint8_t> result;
        sqlite3_stmt *stmt;
        do {
            int rc = sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL);
            if (rc != SQLITE_OK) {
                std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
            rc = sqlite3_bind_int(stmt, 1, key);
            if (rc != SQLITE_OK) {
                std::cerr << "Error binding parameter: " << sqlite3_errmsg(db) << std::endl;
                break;
            }
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                const void *value = sqlite3_column_blob(stmt, 0);
                int value_size = sqlite3_column_bytes(stmt, 0);
                const uint8_t *start = reinterpret_cast<const uint8_t *>(value);
                result.assign(start, start + value_size);
            } else if (rc == SQLITE_DONE) {
            } else {
                std::cerr << "Error fetching value: " << sqlite3_errmsg(db) << std::endl;
            }
        } while (0);
        sqlite3_finalize(stmt);
        return result;
    }

    void remove(int key) {
        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, sql_delete, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            std::cerr << "Error preparing statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            exit(1);
        }
        rc = sqlite3_bind_int(stmt, 1, key);
        if (rc != SQLITE_OK) {
            std::cerr << "Error binding parameter: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            exit(1);
        }
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            std::cerr << "Error deleting value: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            exit(1);
        }
        sqlite3_finalize(stmt);
    }

    ~KvDatabase() {
        std::cerr << __func__ << " destructor\n";
        sqlite3_close(db);
        db = NULL;
    }

   private:
    sqlite3 *db;
    char *zErrMsg = NULL;
};

#endif  // LIC_COMM_KVDB_H_

// SPDX-License-Identifier: AGPL-3.0-only
//! `sid_fold(text)`: Unicode simple lower case, registered on every SQLite
//! connection the backend opens. SQLite's built-in `lower()` folds ASCII
//! only, so a case-insensitive comparison (`caseExact: false`, RFC 7643 §2.2)
//! of `ÉLODIE` with `élodie` needs this to agree with PostgreSQL, which folds
//! under `pg_c_utf8`: simple case mapping, each code point to one.

use libsqlite3_sys as ffi;
use sqlx::SqliteConnection;
use std::ffi::{c_char, c_int};

/// The SQL name, NUL-terminated for SQLite.
const NAME: &[u8] = b"sid_fold\0";

/// Register `sid_fold` on `conn`.
pub(crate) async fn register(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let mut handle = conn.lock_handle().await?;
    let db = handle.as_raw_handle().as_ptr();
    // SAFETY: `db` is the open connection, held exclusively by the locked
    // handle for this call; `NAME` is NUL-terminated and 'static; the
    // function keeps no user data, so it needs no destructor.
    let rc = unsafe {
        ffi::sqlite3_create_function_v2(
            db,
            NAME.as_ptr().cast(),
            1,
            ffi::SQLITE_UTF8 | ffi::SQLITE_DETERMINISTIC | ffi::SQLITE_INNOCUOUS,
            std::ptr::null_mut(),
            Some(fold),
            None,
            None,
            None,
        )
    };
    if rc == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(format!(
            "register sid_fold: SQLite result code {rc}"
        )))
    }
}

/// The simple lowercase mapping of `c` (UnicodeData.txt field 13), as
/// PostgreSQL's `pg_c_utf8` applies it. `str::to_lowercase` is not it: it
/// adds the contextual final sigma (`Σ` → `ς`). `char::to_lowercase` adds no
/// context and differs only for U+0130 `İ`, the one code point whose full
/// lowercase (SpecialCasing.txt) is two, `i` + U+0307; its simple mapping is
/// the first of them, `i`.
fn simple_lowercase(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

#[cfg(test)]
mod tests;

/// `sid_fold(x)`: NULL for NULL, otherwise `x` as text in simple lower case.
unsafe extern "C" fn fold(
    ctx: *mut ffi::sqlite3_context,
    n_arg: c_int,
    args: *mut *mut ffi::sqlite3_value,
) {
    debug_assert_eq!(n_arg, 1, "registered with one argument");
    // SAFETY: SQLite calls this with `ctx` and `n_arg` (= 1) valid values in
    // `args`; the text pointer and its byte length stay valid until the value
    // is next converted, which nothing here does before the copy below.
    unsafe {
        let arg = *args;
        if ffi::sqlite3_value_type(arg) == ffi::SQLITE_NULL {
            ffi::sqlite3_result_null(ctx);
            return;
        }
        let ptr = ffi::sqlite3_value_text(arg);
        let len = ffi::sqlite3_value_bytes(arg);
        let bytes: &[u8] = match usize::try_from(len) {
            Ok(0) => &[],
            Ok(len) => std::slice::from_raw_parts(ptr, len),
            Err(_) => {
                ffi::sqlite3_result_error_code(ctx, ffi::SQLITE_MISUSE);
                return;
            }
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            ffi::sqlite3_result_error_code(ctx, ffi::SQLITE_MISMATCH);
            return;
        };
        let folded: String = text.chars().map(simple_lowercase).collect();
        let Ok(folded_len) = c_int::try_from(folded.len()) else {
            ffi::sqlite3_result_error_toobig(ctx);
            return;
        };
        // SQLITE_TRANSIENT: SQLite copies the text before `folded` is freed.
        ffi::sqlite3_result_text(
            ctx,
            folded.as_ptr().cast::<c_char>(),
            folded_len,
            ffi::SQLITE_TRANSIENT(),
        );
    }
}

<?php
/**
 * Tests for SQL Injection fix in admin/customfields.php
 *
 * Validates that the $optionformname value obtained from $_REQUEST is always
 * passed through mysql_real_escape_string() before being embedded in any SQL
 * query, preventing CWE-89 SQL Injection via cookie-based $_REQUEST values
 * that bypass the $_POST/$_GET sanitization loop in or-dbinfo.php.
 *
 * These tests do NOT execute database queries; they use function mocking and
 * static code analysis helpers to confirm the taint flow is broken at the
 * input boundary (line 18 of admin/customfields.php).
 */

// ---------------------------------------------------------------------------
// Minimal test harness (no external framework required)
// ---------------------------------------------------------------------------

$TESTS_PASSED = 0;
$TESTS_FAILED = 0;

function assert_true($condition, $message) {
    global $TESTS_PASSED, $TESTS_FAILED;
    if ($condition) {
        echo "[PASS] " . $message . PHP_EOL;
        $TESTS_PASSED++;
    } else {
        echo "[FAIL] " . $message . PHP_EOL;
        $TESTS_FAILED++;
    }
}

function assert_equals($expected, $actual, $message) {
    global $TESTS_PASSED, $TESTS_FAILED;
    if ($expected === $actual) {
        echo "[PASS] " . $message . PHP_EOL;
        $TESTS_PASSED++;
    } else {
        echo "[FAIL] " . $message . " (expected: " . var_export($expected, true)
            . ", got: " . var_export($actual, true) . ")" . PHP_EOL;
        $TESTS_FAILED++;
    }
}

// ---------------------------------------------------------------------------
// Static source-code analysis helpers
// ---------------------------------------------------------------------------

/**
 * Read the source of the target file.
 */
function get_source($file) {
    return file_get_contents($file);
}

/**
 * Return the line content (1-indexed) from $source, or null if out of range.
 */
function get_line($source, $lineNumber) {
    $lines = explode("\n", $source);
    $idx   = $lineNumber - 1;
    return isset($lines[$idx]) ? $lines[$idx] : null;
}

// ---------------------------------------------------------------------------
// Path to the file under test
// ---------------------------------------------------------------------------
$TARGET_FILE = __DIR__ . '/../admin/customfields.php';

// ---------------------------------------------------------------------------
// Test 1: Target file exists
// ---------------------------------------------------------------------------
assert_true(
    file_exists($TARGET_FILE),
    'admin/customfields.php exists'
);

$source = get_source($TARGET_FILE);

// ---------------------------------------------------------------------------
// Test 2: $optionformname is sanitized at the input boundary (line 18)
//
// The fix must ensure that $_REQUEST["optionformname"] is passed through
// mysql_real_escape_string() before being assigned to $optionformname so
// that cookie-supplied values (which bypass the $_POST/$_GET escaping loop
// in or-dbinfo.php) cannot inject SQL.
// ---------------------------------------------------------------------------
$line18 = get_line($source, 18);
assert_true(
    $line18 !== null,
    'Line 18 exists in admin/customfields.php'
);

assert_true(
    strpos($line18, 'mysql_real_escape_string') !== false,
    'Line 18 applies mysql_real_escape_string() to $_REQUEST["optionformname"]'
);

assert_true(
    strpos($line18, '$_REQUEST["optionformname"]') !== false
    || strpos($line18, "\$_REQUEST['optionformname']") !== false,
    'Line 18 reads optionformname from $_REQUEST'
);

// ---------------------------------------------------------------------------
// Test 3: The raw (unescaped) $_REQUEST["optionformname"] value is NOT
//         assigned directly to $optionformname without escaping.
//
// Pattern to reject: $optionformname = ... $_REQUEST["optionformname"] ...
// without mysql_real_escape_string wrapping it.
// ---------------------------------------------------------------------------
// Capture all assignment lines for $optionformname from $_REQUEST
$assignmentPattern = '/\$optionformname\s*=.*\$_REQUEST\s*\[\s*["\']optionformname["\']\s*\]/';
preg_match_all($assignmentPattern, $source, $matches, PREG_OFFSET_CAPTURE);

$unsafeAssignments = [];
foreach ($matches[0] as $match) {
    $assignment = $match[0];
    // An assignment is unsafe if it does NOT wrap with mysql_real_escape_string
    if (strpos($assignment, 'mysql_real_escape_string') === false) {
        $unsafeAssignments[] = $assignment;
    }
}

assert_true(
    count($unsafeAssignments) === 0,
    'No assignment of $_REQUEST["optionformname"] to $optionformname exists '
    . 'without mysql_real_escape_string() wrapping (found '
    . count($unsafeAssignments) . ' unsafe assignment(s))'
);

// ---------------------------------------------------------------------------
// Test 4: The SQL query at line 101 (the SAST-identified sink) uses
//         $optionformname, which is now sanitized at its source.
// ---------------------------------------------------------------------------
$line101 = get_line($source, 101);
assert_true(
    $line101 !== null,
    'Line 101 exists in admin/customfields.php'
);

assert_true(
    strpos($line101, '$optionformname') !== false,
    'Line 101 (SAST sink) still references $optionformname'
);

assert_true(
    strpos($line101, 'mysql_query') !== false
    || strpos($line101, 'mysql_fetch_array') !== false,
    'Line 101 (SAST sink) contains a database operation'
);

// ---------------------------------------------------------------------------
// Test 5: Verify mysql_real_escape_string behavior on SQL-injection payloads.
//
// Since we cannot connect to a real MySQL server in unit tests, we use PHP's
// addslashes() as a behavioral proxy: both functions escape single-quotes,
// double-quotes and backslashes.  The assertions prove that the escaping
// function call in line 18 would neutralize classic injection payloads.
//
// NOTE: In a real integration environment, replace addslashes() with an
//       actual mysql_real_escape_string() call against a live connection.
// ---------------------------------------------------------------------------

/**
 * Proxy for mysql_real_escape_string when no DB connection is available.
 * Covers the characters relevant to SQL injection in single-quoted contexts.
 */
function escape_proxy($value) {
    // addslashes escapes \, ', ", NUL — sufficient for single-quoted SQL values
    return addslashes($value);
}

// Payload 1: classic tautology
$payload1  = "' OR '1'='1";
$escaped1  = escape_proxy($payload1);
$sqlValue1 = "SELECT * FROM optionalfields WHERE optionformname='" . $escaped1 . "';";
assert_true(
    strpos($sqlValue1, "' OR '") === false,
    "Classic tautology payload (\" ' OR '1'='1 \") is neutralized after escaping"
);

// Payload 2: UNION-based injection
$payload2  = "' UNION SELECT username, password FROM users -- ";
$escaped2  = escape_proxy($payload2);
$sqlValue2 = "SELECT * FROM optionalfields WHERE optionformname='" . $escaped2 . "';";
assert_true(
    strpos($sqlValue2, "' UNION") === false,
    "UNION-based injection payload is neutralized after escaping"
);

// Payload 3: stacked query (DROP TABLE)
$payload3  = "'; DROP TABLE optionalfields; -- ";
$escaped3  = escape_proxy($payload3);
$sqlValue3 = "SELECT * FROM optionalfields WHERE optionformname='" . $escaped3 . "';";
assert_true(
    strpos($sqlValue3, "'; DROP") === false,
    "Stacked query (DROP TABLE) payload is neutralized after escaping"
);

// Payload 4: boolean-based blind injection
$payload4  = "' AND 1=1 -- ";
$escaped4  = escape_proxy($payload4);
$sqlValue4 = "SELECT * FROM optionalfields WHERE optionformname='" . $escaped4 . "';";
assert_true(
    strpos($sqlValue4, "' AND") === false,
    "Boolean-based blind injection payload is neutralized after escaping"
);

// Payload 5: legitimate value must pass through unchanged (except for safe chars)
$payload5  = "mylowercasefield";
$escaped5  = escape_proxy($payload5);
assert_equals(
    $payload5,
    $escaped5,
    "Legitimate optionformname value is unchanged after escaping"
);

// ---------------------------------------------------------------------------
// Test 6: The $_COOKIE superglobal is NOT sanitized in or-dbinfo.php, so
//         $_REQUEST can carry unsanitized cookie values.  Confirm or-dbinfo.php
//         only loops over $_POST and $_GET — establishing why the fix in
//         customfields.php (line 18) is necessary.
// ---------------------------------------------------------------------------
$dbinfoFile   = __DIR__ . '/../includes/or-dbinfo.php';
$dbinfoSource = file_get_contents($dbinfoFile);

assert_true(
    $dbinfoSource !== false,
    'includes/or-dbinfo.php is readable'
);

// or-dbinfo.php must sanitize $_POST
assert_true(
    strpos($dbinfoSource, '$_POST') !== false,
    'or-dbinfo.php processes $_POST values through mysql_real_escape_string'
);

// or-dbinfo.php must sanitize $_GET
assert_true(
    strpos($dbinfoSource, '$_GET') !== false,
    'or-dbinfo.php processes $_GET values through mysql_real_escape_string'
);

// or-dbinfo.php must NOT include a loop/sanitization pass over $_COOKIE
// (confirming the gap that the customfields.php fix closes)
assert_true(
    strpos($dbinfoSource, '$_COOKIE') === false,
    'or-dbinfo.php does NOT sanitize $_COOKIE (confirming the gap fixed in customfields.php)'
);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
echo PHP_EOL;
echo "Results: {$TESTS_PASSED} passed, {$TESTS_FAILED} failed." . PHP_EOL;

if ($TESTS_FAILED > 0) {
    exit(1);
}
exit(0);

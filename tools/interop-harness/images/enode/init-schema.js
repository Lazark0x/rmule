// Wait for the MySQL sidecar and load eNode's own schema (misc/enode.sql,
// CREATE TABLE IF NOT EXISTS — idempotent). Kept separate from eNode's code so
// eNode's sources stay unmodified (ADR-0045). Retries connection until MySQL is
// accepting, then applies the schema and exits.
var fs = require('fs');
var mysql = require('/opt/enode/src/node_modules/mysql');

var host = process.env.ENODE_MYSQL_HOST || 'enode-mysql';
var user = process.env.ENODE_MYSQL_USER || 'enode';
var pass = process.env.ENODE_MYSQL_PASS || 'password';
var db = process.env.ENODE_MYSQL_DB || 'enode';
var schema = fs.readFileSync('/opt/enode/src/misc/enode.sql', 'utf8');

var attempts = 0;
var maxAttempts = 60;

function tryConnect() {
  attempts++;
  var conn = mysql.createConnection({
    host: host, user: user, password: pass, database: db,
    multipleStatements: true,
  });
  conn.connect(function (err) {
    if (err) {
      if (attempts >= maxAttempts) {
        console.error('init-schema: MySQL unreachable after ' + attempts + ' attempts: ' + err);
        process.exit(1);
      }
      setTimeout(tryConnect, 2000);
      return;
    }
    // enode.sql is load-once (its trailing ALTER TABLE ADD CONSTRAINT is not
    // idempotent), so only apply it when the schema is absent — restarts reuse
    // the existing tables.
    conn.query("SHOW TABLES LIKE 'clients'", function (errShow, rows) {
      if (errShow) {
        console.error('init-schema: SHOW TABLES failed: ' + errShow);
        process.exit(1);
      }
      if (rows.length > 0) {
        console.error('init-schema: schema already present on ' + user + '@' + host + '/' + db);
        conn.end();
        process.exit(0);
      }
      conn.query(schema, function (err2) {
        if (err2) {
          console.error('init-schema: schema load failed: ' + err2);
          process.exit(1);
        }
        console.error('init-schema: schema loaded on ' + user + '@' + host + '/' + db);
        conn.end();
        process.exit(0);
      });
    });
  });
}

tryConnect();

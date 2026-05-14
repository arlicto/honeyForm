<?php
require_once 'db.php';

if (php_sapi_name() !== 'cli') {
    die("This script must be run from the command line.\n");
}

echo "Rebuilding dashboard statistics from raw logs...\n";
stats_rebuild_all();
echo "Done! Dashboard stats are now synchronized.\n";

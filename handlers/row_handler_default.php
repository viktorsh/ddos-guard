<?php
// include ('../DdosGuard/dist/row_handler_default.php');

use sb\DdosGuard\Helper;

return function ($row)
{
    $currentPos = 0;

    $rowData = [];

    $rowData['ip'] = Helper::parseTextIntoChars($row, [false, ' '], 0, $currentPos);

    $date = Helper::parseTextIntoChars($row, ['[', ']'], $currentPos, $currentPos);

    $rowData['unixtime'] = strtotime($date);

    $rowData['request'] = Helper::parseTextIntoChars($row, '"', $currentPos, $currentPos);

    $rowData['status'] = Helper::parseTextIntoChars($row, ' ', $currentPos, $currentPos);;

    $currentPos--;

    $rowData['body_bytes_sent'] = Helper::parseTextIntoChars($row, ' ', $currentPos, $currentPos);

    $rowData['referer'] = Helper::parseTextIntoChars($row, '"', $currentPos, $currentPos);

    $rowData['user_agent'] = Helper::parseTextIntoChars($row, '"', $currentPos, $currentPos);

    $rowData['x_forwarded_for'] = Helper::parseTextIntoChars($row, '"', $currentPos, $currentPos);

    return $rowData;
};
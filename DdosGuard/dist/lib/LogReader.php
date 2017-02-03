<?php
namespace sb\DdosGuard;

class LogReader
{
    public $filePath;
    public $timeFrom;
    public $timeTo;
    public $limit = [];
    public $handlerFilePath;
    public $excludeIp = [];

    protected $handlerFunction;

    protected $lastRowTime;

    function validate()
    {
        if (empty($this->filePath))
            throw new \Exception('Property "filePath" does not set');

        if (!file_exists($this->filePath))
            throw new \Exception('Property "filePath" is incorrect file does not exist');

        if (empty($this->limit))
            throw new \Exception('Property "limit" does not set');

        foreach($this->limit as $limitItem)
        {
            if (empty($limitItem[0]) || empty($limitItem[1]))
                throw new \Exception('Property "limit" is incorrect it must be integer array');

            if (!is_numeric($limitItem[0]) || !is_numeric($limitItem[1]))
                throw new \Exception('Property "limit" is incorrect it must be integer array');
        }

        if ($this->timeFrom && !is_numeric($this->timeFrom))
            throw new \Exception('Property "timeFrom" is incorrect it must be integer');

        if ($this->timeTo && !is_numeric($this->timeTo))
            throw new \Exception('Property "timeTo" is incorrect it must be integer');

        if (!file_exists($this->handlerFilePath))
            throw new \Exception('Property "handlerFilePath" is incorrect it must be path to file');

        $this->handlerFunction = include ($this->handlerFilePath);

        if (!is_object($this->handlerFunction) || get_class($this->handlerFunction) !== 'Closure')
            throw new \Exception('Content of file "'.$this->handlerFilePath.'" is incorrect it must be callback function');
    }

    function __construct($filePath, $limit = [])
    {
        $this->filePath = $filePath;
        $this->limit = $limit;
    }

    function validateRowData($rowData)
    {
        if (!$rowData['ip'])
            throw new \Exception('Property "ip" is not defined');

        if (!ip2long($rowData['ip']))
            throw new \Exception('Property "ip" is incorrect');

        if (!$rowData['status'])
            throw new \Exception('Property "status" is not defined');

        if (!is_numeric($rowData['status']))
            throw new \Exception('Property "status" is incorrect');

        if (!$rowData['unixtime'])
            throw new \Exception('Property "unixtime" is not defined');
    }

    function read()
    {
        $this->validate();

        $fp = fopen($this->filePath, 'r');

        $arIpBan = [];

        while(!feof($fp))
        {
            $row = fgets($fp);

            $row = trim($row);

            if (!$row)
                continue;

            $func = $this->handlerFunction;
            $rowData = $func($row);

            try
            {
                $this->validateRowData($rowData);
            }
            catch(\Exception $e)
            {
                // Выбрасываем ошибку валидации дальше
                throw new \Exception('Log parser error. ' . $e->getMessage());
            }

            $this->lastRowTime = $rowData['unixtime'];

            if ($this->timeFrom && $rowData['unixtime'] < $this->timeFrom)
                continue;

            if ($this->timeTo && $rowData['unixtime'] < $this->timeTo)
                continue;

            if ($rowData['status'] != 200)
                continue;

            $ip = $rowData['ip'];

            if (in_array($ip, $this->excludeIp))
                continue;

            $arIp[$ip][] = $rowData;

            if (count($arIp[$ip])>$this->limit[0][0])
            {
                array_shift($arIp[$ip]);

                reset($arIp[$ip]);
                $firstRowData = current($arIp[$ip]);

                $currentPeriod = $rowData['unixtime'] - $firstRowData['unixtime'];

                if($currentPeriod < $this->limit[0][1])
                {
                    if (empty($arIpBan[$ip]))
                        $arIpBan[$ip] = 0;

                    $arIpBan[$ip] ++;
                }
            }
        }

        fclose($fp);

        return $arIpBan;
    }

    public function getLastRowTime()
    {
        return $this->lastRowTime;
    }
}
?>

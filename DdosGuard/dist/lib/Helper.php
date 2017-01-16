<?php
namespace sb\DdosGuard;

/**
 * Created by PhpStorm.
 * User: viktor
 * Date: 10.01.2017
 * Time: 15:49
 */


class Helper
{
    static function parseTextIntoChars($str, $char, $offset = 0, &$returnPos = false)
    {
        if (!is_array($char))
        {
            $arChar = [$char, $char];
        }
        else
        {
            $arChar = $char;

            if (count($arChar)<2)
                $arChar[1] = $arChar[0];
        }

        if ($arChar[0])
            $posStart = strpos($str, $arChar[0], $offset);
        else
            $posStart = $offset;

        if ($posStart === false)
            return false;

        $posStart += mb_strlen($arChar[0]);

        $pos = $posStart;
        while(1)
        {
            $posEnd = strpos($str, $arChar[1], $pos);

            if (!$posEnd)
                break;

            if (substr($str, $posEnd-1, 1) != '\\')
                break;

            $pos = $posEnd + mb_strlen($arChar[0]);
        }

        $returnPos = $posEnd + 1;

        return substr($str, $posStart, $posEnd - $posStart);
    }

    static function validateIp($ip)
    {
        return (bool)ip2long($ip);
    }
}
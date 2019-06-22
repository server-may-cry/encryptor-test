<?php
declare(strict_types=1);

namespace Task\Encryptor;

abstract class EncryptorException extends \Exception
{
}
final class InvalidStringCharacterException extends EncryptorException
{
}
final class InternalEncryptorException extends EncryptorException
{
}

interface EncryptorInterface {
    /**
     * The only valid input and output characters for all variables are from SPACE (character 32) through
     * to TILDE (character 126). The encryptionKey must not be empty.
     *
     * @return string ecrypted text
     * @throws EncryptorException when any character of input string don't match criteria, or internal error happens
     */
    public function encrypt(string $textToEncrypt, string $encryptionKey): string;

    /**
     * The only valid input and output characters for all variables are from SPACE (character 32) through
     * to TILDE (character 126). The encryptionKey must not be empty.
     *
     * @return string original text
     * @throws EncryptorException when any character of input string don't match criteria, or internal error happens
     */
    public function decrypt(string $encryptedText, string $encryptionKey): string;
}

final class Encryptor implements EncryptorInterface {
    // This variable could be declared static for reuse when several instance will be created.
    private $primeNumbersCache = [
        2,
        3,
    ];
    private const CHARACTER_RANGE_LENGTH = 126 - 31;

    public function encrypt(string $textToEncrypt, string $encryptionKey): string
    {
        if (mb_strlen($textToEncrypt) !== strlen($textToEncrypt) || mb_strlen($encryptionKey) !== strlen($encryptionKey)) {
            throw new InvalidStringCharacterException('Multi bytes strings not supported');
        }

        $encruptedString = '';
        for ($position = 0; $position < mb_strlen($textToEncrypt); ++$position) {
            $correspondingCharacterValueInTheEncryptionKey = $this->getASCIICharacterValue(
                $this->getSymbolFromStringWithOverSize($position, $encryptionKey)
            );
            $n = $position + $correspondingCharacterValueInTheEncryptionKey;
            $primeForN = $this->getPrimeNumber($n);

            $rawEncryptedSymbol = $primeForN + $position + $this->getASCIICharacterValue(
                $textToEncrypt[$position]
            );
            $encryptedCharacterValue = $this->wrapCharacterBackIntoRange($rawEncryptedSymbol);

            $encruptedString .= $this->getASCIICharacter($encryptedCharacterValue);
        }

        return $encruptedString;
    }

    public function decrypt(string $encruptedString, string $encryptionKey): string
    {
        if (mb_strlen($encruptedString) !== strlen($encruptedString) || mb_strlen($encryptionKey) !== strlen($encryptionKey)) {
            throw new InvalidStringCharacterException('Multi bytes strings not supported');
        }

        $decruptedString = '';
        for ($position = 0; $position < mb_strlen($encruptedString); ++$position) {
            $correspondingCharacterValueInTheEncryptionKey = $this->getASCIICharacterValue(
                $this->getSymbolFromStringWithOverSize($position, $encryptionKey)
            );
            $n = $position + $correspondingCharacterValueInTheEncryptionKey;
            $primeForN = $this->getPrimeNumber($n);

            $unwrappedSymbolValue = $this->wrapCharacterBackIntoRange(
                $this->getASCIICharacterValue($encruptedString[$position]) - $primeForN - $position
            );

            $decruptedString .= $this->getASCIICharacter($unwrappedSymbolValue);
        }

        return $decruptedString;
    }

    /**
     * Get symbol from string with support of index higher than range.
     * For example:
     *   - String "abc" with index 0 will return "a"
     *   - String "abc" with index 1 will return "b"
     *   - String "abc" with index 2 will return "c"
     *   - String "abc" with index 3 will return "a"
     */
    private function getSymbolFromStringWithOverSize(int $symbolNumber, string $string): string
    {
        if (0 > $symbolNumber) {
            throw new InternalEncryptorException(
                sprintf('Negative offset not supported. "%d" given.', $symbolNumber)
            );
        }
        $symbolNumberInStringRange = $symbolNumber % mb_strlen($string);

        return $string[$symbolNumberInStringRange];
    }

    private function getASCIICharacterValue(string $symbol): int
    {
        $value = ord($symbol);
        if (32 > $value || 126 < $value) {
            throw new InvalidStringCharacterException(
                sprintf('Symbol "%s" don`t meet criteria. Symbol value: "%d"', $symbol, $value)
            );
        }

        return $value;
    }

    private function getASCIICharacter(int $val): string
    {
        return chr($val);
    }

    /**
     * @see https://en.wikipedia.org/wiki/Prime_number
     */
    private function getPrimeNumber(int $num): int
    {
        if (0 > $num) {
            throw new InternalEncryptorException(
                sprintf('Prive numbers with negative index not supported. "%d" given.', $num)
            );
        }

        if (array_key_exists($num, $this->primeNumbersCache)) {
            return $this->primeNumbersCache[$num];
        }

        $lastPrimeNumber = end($this->primeNumbersCache);

        $newPrimeNumber = $lastPrimeNumber;
        while(true) {
            $newPrimeNumber += 2; // We can speed up prime number search since all even numbers are not prime by definition of even number
            foreach ($this->primeNumbersCache as $i => $number) {
                if (0 === $newPrimeNumber % $number) {
                    continue 2;
                }
            }
            $lastPrimeNumber = $newPrimeNumber;
            $this->primeNumbersCache[] = $lastPrimeNumber;

            if (array_key_exists($num, $this->primeNumbersCache)) {
                return $this->primeNumbersCache[$num];
            }
        }
    }

    /**
     * Fit integer into range from 32 to 126.
     * For example:
     *   - 127 becames 32
     *   - 128 becames 33
     *   - 31 becames 126
     *   - 30 becames 125
     */
    public function wrapCharacterBackIntoRange(int $value): int
    {
        $value -= 32;
        $valueInRange = $value % self::CHARACTER_RANGE_LENGTH;
        if (0 > $valueInRange) {
            $valueInRange += self::CHARACTER_RANGE_LENGTH;
        }

        $valueInRange += 32;

        return $valueInRange;
    }
}


// Example of usage
$textToEncrypt = 'secret message';
$encryptionKey = 'key';
$encryptor = new Encryptor();

$encryptedMessage = $encryptor->encrypt($textToEncrypt, $encryptionKey);
$decryptedMessage = $encryptor->decrypt($encryptedMessage, $encryptionKey);

echo 'Original message : '.$textToEncrypt.PHP_EOL;
echo 'Encryption key   : '.$encryptionKey.PHP_EOL;
echo 'Encrypted message: '.$encryptedMessage.PHP_EOL;
echo 'Decrypted message: '.$decryptedMessage.PHP_EOL;

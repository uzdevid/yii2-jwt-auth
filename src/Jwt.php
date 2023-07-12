<?php

namespace uzdevid\jwt\auth;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT as BaseJwt;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use stdClass;
use yii\base\Component;
use yii\base\InvalidConfigException;
use UnexpectedValueException;
use InvalidArgumentException;

/**
 * Class Jwt
 * @package uzdevid\jwt\auth
 *
 * @property string $secretKey
 * @property int $duration
 * @property string $algo
 */
class Jwt extends Component {

    public const ALGO_HS256 = 'HS256';
    public const ALGO_HS384 = 'HS384';
    public const ALGO_HS512 = 'HS512';
    public const ALGO_RS256 = 'RS256';
    public const ALGO_RS384 = 'RS384';
    public const ALGO_RS512 = 'RS512';
    public const ALGO_ES256 = 'ES256';
    public const ALGO_ES384 = 'ES384';
    public const ALGO_ES512 = 'ES512';
    public const ALGO_PS256 = 'PS256';
    public const ALGO_PS384 = 'PS384';
    public const ALGO_PS512 = 'PS512';

    public static array $algos = [
        self::ALGO_HS256,
        self::ALGO_HS384,
        self::ALGO_HS512,
        self::ALGO_RS256,
        self::ALGO_RS384,
        self::ALGO_RS512,
        self::ALGO_ES256,
        self::ALGO_ES384,
        self::ALGO_ES512,
        self::ALGO_PS256,
        self::ALGO_PS384,
        self::ALGO_PS512,
    ];

    private string $_secretKey = 'default';
    private int $_duration = 300;
    private string $_algo = 'HS256';

    public function encode(array $payload): string {
        return BaseJwt::encode($payload, $this->secretKey, $this->algo);
    }

    public function decode(string $token, string|null $payloadClass = null): stdClass|false {
        try {
            return BaseJwt::decode($token, new Key($this->secretKey, $this->algo));
        } catch (InvalidArgumentException|UnexpectedValueException|SignatureInvalidException|BeforeValidException|ExpiredException $e) {
            return false;
        }
    }

    /**
     * @return string
     */
    public function getSecretKey(): string {
        return $this->_secretKey;
    }

    /**
     * @param string $secretKey
     */
    public function setSecretKey(string $secretKey): void {
        $this->_secretKey = $secretKey;
    }

    /**
     * @return int
     */
    public function getDuration(): int {
        return $this->_duration;
    }

    /**
     * @param int $duration
     */
    public function setDuration(int $duration): void {
        $this->_duration = $duration;
    }

    /**
     * @return string
     */
    public function getAlgo(): string {
        return $this->_algo;
    }

    /**
     * @param string $algo
     * @throws InvalidConfigException
     */
    public function setAlgo(string $algo): void {
        if (!in_array($algo, self::$algos)) {
            throw new InvalidConfigException('Invalid algorithm');
        }

        $this->_algo = $algo;
    }
}
<?php

namespace uzdevid\jwt\auth\bearer;

use Yii;
use yii\base\InvalidConfigException;
use yii\filters\auth\AuthMethod;
use yii\web\IdentityInterface;
use yii\web\UnauthorizedHttpException;

class JwtBearerAuth extends AuthMethod {
    public string $header = 'Authorization';
    public string $pattern = '/^Bearer\s+(.*?)$/';
    public string $jwt = 'jwt';

    /**
     * @inheritdoc
     *
     * @throws InvalidConfigException
     * @throws UnauthorizedHttpException
     */
    public function authenticate($user, $request, $response): IdentityInterface|null {
        if (!Yii::$app->has($this->jwt)) {
            throw new InvalidConfigException("The \"{$this->jwt}\" property must be set.");
        }

        $bearer = $request->headers->get($this->header);

        if (is_null($bearer)) {
            throw new UnauthorizedHttpException('Missing authorization header');
        }

        if (!preg_match($this->pattern, $bearer, $matches)) {
            throw new UnauthorizedHttpException('Invalid authorization header');
        }

        $jwt = Yii::$app->get($this->jwt);

        if (($payload = $jwt->decode($matches[1])) === false) {
            throw new UnauthorizedHttpException('Invalid token');
        }

        $exp = $payload->iat + $jwt->duration;

        if (time() > $exp) {
            throw new UnauthorizedHttpException('Token expired');
        }

        $identity = $user->loginByAccessToken($payload->sub, get_class($this));

        if ($identity === null) {
            $this->challenge($response);
            $this->handleFailure($response);
        }

        return $identity;
    }
}
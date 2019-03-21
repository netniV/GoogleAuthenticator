<?php

declare(strict_types=1);

/*
 * This file is part of the Sonata Project package.
 *
 * (c) Thomas Rabaix <thomas.rabaix@sonata-project.org>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Sonata\GoogleAuthenticator\tests;

use Sonata\GoogleAuthenticator\GoogleAuthenticator;

class GoogleAuthenticatorTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var \Sonata\GoogleAuthenticator\GoogleAuthenticator
     */
    protected $helper;

    /**
     * Asserts that the given callback throws the given exception.
     *
     * @param string $expectClass The name of the expected exception class
     * @param callable $callback A callback which should throw the exception
     */
    protected function assertException(string $expectClass, callable $callback)
    {
        try {
            $callback();
        } catch (\Throwable $exception) {
            $this->assertInstanceOf($expectClass, $exception, 'An invalid exception was thrown');
            return;
        }

        $this->fail('No exception was thrown');
    }

    public function setUp(): void
    {
        $this->helper = new GoogleAuthenticator();
    }

    public function testGenerateSecret(): void
    {
        $this->assertSame(
            16,
            \strlen($this->helper->generateSecret())
        );
    }

    /**
     * @group legacy
     * @expectedDeprecation Passing anything other than null or a DateTimeInterface to $time is deprecated as of 2.0 and will not be possible as of 3.0.
     * @dataProvider testCheckCodeData
     */
    public function testCheckCodeWithLegacyArguments($expectation, $inputDate): void
    {
        $authenticator = new GoogleAuthenticator(6, 10, new \DateTime('2012-03-17 22:17:00'));
        $this->assertSame(
            $expectation,
            $authenticator->checkCode('3DHTQX4GCRKHGS55CJ', $authenticator->getCode('3DHTQX4GCRKHGS55CJ', strtotime($inputDate) / 30))
        );
    }

    /**
     * @dataProvider testCheckCodeData
     */
    public function testCheckCode($expectation, $inputDate): void
    {
        $authenticator = new GoogleAuthenticator(6, 10, new \DateTime('2012-03-17 22:17:00'));

        try {
            $datetime = new \DateTime($inputDate);
        } catch (\Exception $e) {
            return;
        }

        $this->assertSame(
            $expectation,
            $authenticator->checkCode('3DHTQX4GCRKHGS55CJ', $authenticator->getCode('3DHTQX4GCRKHGS55CJ', $datetime))
        );
    }

    /**
     * all dates compare to the same date + or - the several seconds compared
     * to 22:17:00 to verify if the code was perhaps the previous or next 30
     * seconds. This ensures that slow entries or time delays are not causing
     * problems.
     *
     * @return array
     */
    public static function testCheckCodeData(): array
    {
        return [
            [false, '2012-03-17 22:16:29'],
            [true, '2012-03-17 22:16:30'],
            [true, '2012-03-17 22:17:00'],
            [true, '2012-03-17 22:17:30'],
            [false, '2012-03-17 22:18:00'],
            [false, 'this date cannot be resolved and results into false'],
        ];
    }

    public function testGetCodeReturnsDefinedLength(): void
    {
        $authenticator = new GoogleAuthenticator(8, 10, new \DateTime('2012-03-17 22:17:00'));

        for ($a = 0; $a < 1000; ++$a) {
            $this->assertSame(8, \strlen($authenticator->getCode($authenticator->generateSecret())));
        }
    }

    /**
     * @group legacy
     * @expectedDeprecation Using Sonata\GoogleAuthenticator\GoogleAuthenticator::getUrl() is deprecated as of 2.1 and will be removed in 3.0. Use Sonata\GoogleAuthenticator\GoogleQrUrl::generate() instead.
     */
    public function testGetUrlIssuer(): void
    {
        $this->assertSame(
            'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Ffoo%40foobar.org%3Fsecret%3D3DHTQX4GCRKHGS55CJ%26issuer%3DFooBar',
            $this->helper->getUrl('foo', 'foobar.org', '3DHTQX4GCRKHGS55CJ', 'FooBar')
        );
    }

    /**
     * @group legacy
     * @expectedDeprecation Using Sonata\GoogleAuthenticator\GoogleAuthenticator::getUrl() is deprecated as of 2.1 and will be removed in 3.0. Use Sonata\GoogleAuthenticator\GoogleQrUrl::generate() instead.
     */
    public function testGetUrlNoIssuer(): void
    {
        $this->assertSame(
            'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2Ffoo%40foobar.org%3Fsecret%3D3DHTQX4GCRKHGS55CJ',
            $this->helper->getUrl('foo', 'foobar.org', '3DHTQX4GCRKHGS55CJ')
        );
    }

    public function testCodePeriodValid(): void
    {
        $authenticator = new GoogleAuthenticator(8, 10, new \DateTime('2012-03-17 22:17:00'));
        $this->assertFalse($authenticator->setCodePeriod(300));
        $this->assertSame(300, $authenticator->getCodePeriod());
    }

    public function testCodePeriodInvalidNegative(): void
    {
        $authenticator = new GoogleAuthenticator(8, 10, new \DateTime('2012-03-17 22:17:00'));
        $this->assertException('InvalidArgumentException', function() { $authenticator->setCodePeriod(-30); });
        $this->assertSame(30, $authenticator->getCodePeriod());
    }

    public function testCodePeriodInvalidMin(): void
    {
        $authenticator = new GoogleAuthenticator(8, 10, new \DateTime('2012-03-17 22:17:00'));
        $this->assertException('InvalidArgumentException', function() { $authenticator->setCodePeriod(0); });
        $this->assertSame(30, $authenticator->getCodePeriod());
    }

    public function testCodePeriodInvalidMax(): void
    {
        $authenticator = new GoogleAuthenticator(8, 10, new \DateTime('2012-03-17 22:17:00'));
        $this->assertException('InvalidArgumentException', function() { $authenticator->setCodePeriod(86401); });
        $this->assertSame(30, $authenticator->getCodePeriod());
    }
}

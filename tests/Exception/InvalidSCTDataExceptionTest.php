<?php

declare(strict_types=1);

namespace Tourze\TLSCertExtensions\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCertExtensions\Exception\InvalidSCTDataException;

/**
 * @internal
 */
#[CoversClass(InvalidSCTDataException::class)]
final class InvalidSCTDataExceptionTest extends AbstractExceptionTestCase
{
    public function testExceptionIsThrowable(): void
    {
        $this->expectException(InvalidSCTDataException::class);
        $this->expectExceptionMessage('Invalid SCT data');

        throw new InvalidSCTDataException('Invalid SCT data');
    }

    public function testExceptionExtendsInvalidArgumentException(): void
    {
        $exception = new InvalidSCTDataException('Test message');

        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
    }

    public function testExceptionWithCustomMessage(): void
    {
        $message = 'Custom error message';
        $exception = new InvalidSCTDataException($message);

        $this->assertEquals($message, $exception->getMessage());
    }

    public function testExceptionWithCodeAndPrevious(): void
    {
        $previousException = new \Exception('Previous error');
        $exception = new InvalidSCTDataException('Test error', 123, $previousException);

        $this->assertEquals('Test error', $exception->getMessage());
        $this->assertEquals(123, $exception->getCode());
        $this->assertSame($previousException, $exception->getPrevious());
    }
}

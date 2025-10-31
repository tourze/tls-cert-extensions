<?php

declare(strict_types=1);

namespace Tourze\TLSCertExtensions\Tests\Certificate;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertExtensions\Certificate\SCTValidator;

/**
 * 证书透明度(SCT)验证器测试类
 *
 * @internal
 */
#[CoversClass(SCTValidator::class)]
final class SCTValidatorTest extends TestCase
{
    /**
     * 测试解析SCT数据
     */
    public function testParseSCTData(): void
    {
        // 准备测试数据
        // 由于SCT数据格式很复杂，我们需要保证列表长度和实际数据长度一致

        // 创建一个非常简单的SCT数据用于测试
        $version = chr(0); // 版本 V1
        $logId = str_repeat('A', 32); // 日志ID (32字节)
        $timestamp = str_repeat(chr(0), 8); // 8字节时间戳 (全零)
        $extensionsLength = pack('n', 0); // 扩展长度 (0)
        $hashAlgorithm = chr(4); // SHA-256
        $signatureAlgorithm = chr(3); // ECDSA
        $signatureData = str_repeat('B', 64); // 64字节签名
        $signatureLength = pack('n', 64); // 签名长度

        // 单个SCT数据
        $sctData = $version . $logId . $timestamp . $extensionsLength .
                   $hashAlgorithm . $signatureAlgorithm . $signatureLength . $signatureData;

        // 计算SCT数据长度 (1 + 32 + 8 + 2 + 1 + 1 + 2 + 64)
        $sctLength = strlen($sctData);
        $sctLengthPacked = pack('n', $sctLength);

        // 列表总长度等于SCT长度加上SCT长度字段长度
        $totalLength = $sctLength + 2;
        $totalLengthPacked = pack('n', $totalLength);

        // 完整的SCT列表数据
        $fullData = $totalLengthPacked . $sctLengthPacked . $sctData;

        // 验证SCT格式
        $validator = new SCTValidator();
        $result = $validator->parseSCTList($fullData);
        $this->assertCount(1, $result);

        $sct = $result[0];
        $this->assertIsArray($sct);
        $this->assertArrayHasKey('version', $sct);
        $this->assertEquals(0, $sct['version']);
        $this->assertArrayHasKey('logId', $sct);
        $this->assertEquals(str_repeat('A', 32), $sct['logId']);
        $this->assertArrayHasKey('timestamp', $sct);
        $this->assertArrayHasKey('signature', $sct);
        $this->assertIsArray($sct['signature']);
        $this->assertArrayHasKey('hashAlgorithm', $sct['signature']);
        $this->assertEquals(4, $sct['signature']['hashAlgorithm']);
        $this->assertArrayHasKey('signatureAlgorithm', $sct['signature']);
        $this->assertEquals(3, $sct['signature']['signatureAlgorithm']);
        $this->assertArrayHasKey('signatureData', $sct['signature']);
        $this->assertEquals(str_repeat('B', 64), $sct['signature']['signatureData']);
    }

    /**
     * 测试验证有效的SCT
     */
    public function testValidateSCT(): void
    {
        // 创建一个测试用的验证器，模拟成功的签名验证
        $validator = new class extends SCTValidator {
            protected function fetchLogPublicKey(string $logId): string
            {
                return "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n";
            }

            protected function verifySignature(string $data, string $signature, string $publicKey, int $hashAlgorithm, int $signatureAlgorithm): bool
            {
                return true;
            }
        };

        $sct = [
            'version' => 0, // SCT版本应该是0，不是1
            'logId' => str_repeat('A', 32),
            'timestamp' => time(),
            'extensions' => '',
            'signature' => [
                'hashAlgorithm' => 4, // SHA-256
                'signatureAlgorithm' => 3, // ECDSA
                'signatureData' => str_repeat('B', 128),
            ],
        ];

        $certificate = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        $tbsCertificate = str_repeat('C', 512); // 证书的TBS部分

        $result = $validator->validateSCT($sct, $certificate, $tbsCertificate);

        $this->assertTrue($result);
    }

    /**
     * 测试验证无效的SCT
     */
    public function testValidateInvalidSCT(): void
    {
        // 创建一个测试用的验证器，模拟失败的签名验证
        $validator = new class extends SCTValidator {
            protected function fetchLogPublicKey(string $logId): string
            {
                return "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n";
            }

            protected function verifySignature(string $data, string $signature, string $publicKey, int $hashAlgorithm, int $signatureAlgorithm): bool
            {
                return false;
            }
        };

        $sct = [
            'version' => 0, // SCT版本应该是0，不是1
            'logId' => str_repeat('A', 32),
            'timestamp' => time(),
            'extensions' => '',
            'signature' => [
                'hashAlgorithm' => 4, // SHA-256
                'signatureAlgorithm' => 3, // ECDSA
                'signatureData' => str_repeat('B', 128),
            ],
        ];

        $certificate = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";
        $tbsCertificate = str_repeat('C', 512); // 证书的TBS部分

        $result = $validator->validateSCT($sct, $certificate, $tbsCertificate);

        $this->assertFalse($result);
    }

    /**
     * 测试解析SCT列表
     */
    public function testParseSCTList(): void
    {
        // 创建包含多个SCT的复杂列表
        $version = chr(0); // 版本 V1
        $logId1 = str_repeat('A', 32); // 第一个日志ID
        $logId2 = str_repeat('B', 32); // 第二个日志ID
        $timestamp = str_repeat(chr(0), 8); // 时间戳
        $extensionsLength = pack('n', 0); // 扩展长度 (0)
        $hashAlgorithm = chr(4); // SHA-256
        $signatureAlgorithm = chr(3); // ECDSA
        $signatureData = str_repeat('C', 64); // 签名数据
        $signatureLength = pack('n', 64);

        // 创建两个SCT
        $sct1 = $version . $logId1 . $timestamp . $extensionsLength .
                $hashAlgorithm . $signatureAlgorithm . $signatureLength . $signatureData;
        $sct2 = $version . $logId2 . $timestamp . $extensionsLength .
                $hashAlgorithm . $signatureAlgorithm . $signatureLength . $signatureData;

        // 构建完整的SCT列表
        $sct1Length = pack('n', strlen($sct1));
        $sct2Length = pack('n', strlen($sct2));

        $sctListData = $sct1Length . $sct1 . $sct2Length . $sct2;
        $totalLength = pack('n', strlen($sctListData));
        $fullData = $totalLength . $sctListData;

        $validator = new SCTValidator();
        $result = $validator->parseSCTList($fullData);

        $this->assertCount(2, $result);

        // 验证第一个SCT
        $this->assertIsArray($result[0]);
        $this->assertEquals(0, $result[0]['version']);
        $this->assertEquals($logId1, $result[0]['logId']);
        $this->assertIsArray($result[0]['signature']);
        $this->assertEquals(4, $result[0]['signature']['hashAlgorithm']);

        // 验证第二个SCT
        $this->assertIsArray($result[1]);
        $this->assertEquals(0, $result[1]['version']);
        $this->assertEquals($logId2, $result[1]['logId']);
        $this->assertIsArray($result[1]['signature']);
        $this->assertEquals(4, $result[1]['signature']['hashAlgorithm']);
    }

    /**
     * 测试验证包含SCT扩展的证书
     */
    public function testValidateCertificateWithSCTExtension(): void
    {
        // 创建一个简单的SCT数据，和testParseSCTData中使用的结构一致
        $version = chr(0); // 版本 V1
        $logId = str_repeat('A', 32); // 日志ID (32字节)
        $timestamp = str_repeat(chr(0), 8); // 8字节时间戳 (全零)
        $extensionsLength = pack('n', 0); // 扩展长度 (0)
        $hashAlgorithm = chr(4); // SHA-256
        $signatureAlgorithm = chr(3); // ECDSA
        $signatureData = str_repeat('B', 64); // 64字节签名
        $signatureLength = pack('n', 64); // 签名长度

        // 单个SCT数据
        $sctData = $version . $logId . $timestamp . $extensionsLength .
                   $hashAlgorithm . $signatureAlgorithm . $signatureLength . $signatureData;

        // 计算SCT数据长度
        $sctLength = strlen($sctData);
        $sctLengthPacked = pack('n', $sctLength);

        // 列表总长度等于SCT长度加上SCT长度字段长度
        $totalLength = $sctLength + 2;
        $totalLengthPacked = pack('n', $totalLength);

        // 完整的SCT列表数据
        $fullData = $totalLengthPacked . $sctLengthPacked . $sctData;

        // 创建一个测试用的验证器
        $validator = new class($fullData) extends SCTValidator {
            private string $sctData;

            public function __construct(string $sctData)
            {
                $this->sctData = $sctData;
            }

            protected function extractSCTFromCertificate(string $certificate): string
            {
                return $this->sctData;
            }

            protected function extractTBSCertificate(string $certificate): string
            {
                return str_repeat('C', 512);
            }

            protected function fetchLogPublicKey(string $logId): string
            {
                return "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n";
            }

            protected function verifySignature(string $data, string $signature, string $publicKey, int $hashAlgorithm, int $signatureAlgorithm): bool
            {
                return true;
            }
        };

        $certificate = "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n";

        $result = $validator->validateCertificate($certificate);

        $this->assertTrue($result);
    }
}

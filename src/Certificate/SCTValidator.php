<?php

declare(strict_types=1);

namespace Tourze\TLSCertExtensions\Certificate;

use Tourze\TLSCertExtensions\Exception\InvalidSCTDataException;

/**
 * 证书透明度(SCT)验证器
 */
class SCTValidator
{
    /**
     * SCT版本
     */
    private const SCT_VERSION_V1 = 0;

    /**
     * 哈希算法：SHA1
     */
    private const HASH_ALGO_SHA1 = 2;

    /**
     * 哈希算法：SHA256
     */
    private const HASH_ALGO_SHA256 = 4;

    /**
     * 签名算法：RSA
     */
    private const SIG_ALGO_RSA = 1;

    /**
     * 签名算法：ECDSA
     */
    private const SIG_ALGO_ECDSA = 3;

    /**
     * 证书扩展OID：SCT扩展
     */
    private const SCT_EXTENSION_OID = '1.3.6.1.4.1.11129.2.4.2';

    /**
     * 解析SCT列表二进制数据
     *
     * @param string $data SCT列表二进制数据
     *
     * @return array<array{version: int, logId: string, timestamp: int, extensions: string, signature: array{hashAlgorithm: int, signatureAlgorithm: int, signatureData: string}}> 解析后的SCT列表
     *
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    public function parseSCTList(string $data): array
    {
        $offset = 0;
        $dataLen = strlen($data);

        // SCT列表总长度
        if ($dataLen < 2) {
            throw new InvalidSCTDataException('SCT列表数据过短');
        }

        $sctListLength = (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
        $offset += 2;

        if ($offset + $sctListLength > $dataLen) {
            throw new InvalidSCTDataException('SCT列表长度超出数据范围');
        }

        $scts = [];

        // 解析每个SCT
        while ($offset < $dataLen) {
            // SCT长度
            if ($offset + 2 > $dataLen) {
                throw new InvalidSCTDataException('SCT长度字段数据不足');
            }

            $sctLength = (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
            $offset += 2;

            if ($offset + $sctLength > $dataLen) {
                throw new InvalidSCTDataException('SCT数据长度超出范围');
            }

            $sct = $this->parseSingleSCT(substr($data, $offset, $sctLength));
            $scts[] = $sct;

            $offset += $sctLength;
        }

        return $scts;
    }

    /**
     * 解析单个SCT数据
     *
     * @param string $data 单个SCT的二进制数据
     *
     * @return array{version: int, logId: string, timestamp: int, extensions: string, signature: array{hashAlgorithm: int, signatureAlgorithm: int, signatureData: string}} 解析后的SCT数据
     *
     * @throws \InvalidArgumentException 如果数据格式无效
     */
    private function parseSingleSCT(string $data): array
    {
        $offset = 0;
        $dataLen = strlen($data);

        // 至少需要1字节版本 + 32字节日志ID + 8字节时间戳 + 2字节扩展长度 + 2字节签名长度
        if ($dataLen < 45) {
            throw new InvalidSCTDataException('SCT数据过短');
        }

        // 版本
        $version = ord($data[$offset]);
        ++$offset;

        if (self::SCT_VERSION_V1 !== $version) {
            throw new InvalidSCTDataException('不支持的SCT版本: ' . $version);
        }

        // 日志ID (32字节)
        $logId = substr($data, $offset, 32);
        $offset += 32;

        // 时间戳 (8字节)
        $timestamp = 0;
        for ($i = 0; $i < 8; ++$i) {
            $timestamp = ($timestamp << 8) | ord($data[$offset + $i]);
        }
        $offset += 8;

        // 扩展 (2字节长度 + 数据)
        $extensionsLength = (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
        $offset += 2;

        if ($offset + $extensionsLength > $dataLen) {
            throw new InvalidSCTDataException('SCT扩展数据长度超出范围');
        }

        $extensions = substr($data, $offset, $extensionsLength);
        $offset += $extensionsLength;

        // 签名
        if ($offset + 4 > $dataLen) {
            throw new InvalidSCTDataException('SCT签名数据不足');
        }

        $hashAlgorithm = ord($data[$offset]);
        ++$offset;

        $signatureAlgorithm = ord($data[$offset]);
        ++$offset;

        $signatureLength = (ord($data[$offset]) << 8) | ord($data[$offset + 1]);
        $offset += 2;

        if ($offset + $signatureLength > $dataLen) {
            throw new InvalidSCTDataException('SCT签名数据长度超出范围');
        }

        $signatureData = substr($data, $offset, $signatureLength);

        return [
            'version' => $version,
            'logId' => $logId,
            'timestamp' => $timestamp,
            'extensions' => $extensions,
            'signature' => [
                'hashAlgorithm' => $hashAlgorithm,
                'signatureAlgorithm' => $signatureAlgorithm,
                'signatureData' => $signatureData,
            ],
        ];
    }

    /**
     * 验证证书中的SCT
     *
     * @param string $certificate X.509证书
     *
     * @return bool 验证结果
     */
    public function validateCertificate(string $certificate): bool
    {
        // 提取证书中的SCT扩展
        $sctData = $this->extractSCTFromCertificate($certificate);
        if (false === $sctData) {
            return false; // 没有SCT扩展
        }

        try {
            // 解析SCT列表
            $scts = $this->parseSCTList($sctData);
            if ([] === $scts) {
                return false;
            }

            // 提取证书的TBS部分
            $tbsCertificate = $this->extractTBSCertificate($certificate);
            if (false === $tbsCertificate) {
                return false;
            }

            // 验证每个SCT
            foreach ($scts as $sct) {
                if ($this->validateSCT($sct, $certificate, $tbsCertificate)) {
                    return true; // 只要有一个SCT有效就返回成功
                }
            }

            return false;
        } catch (\Throwable $e) {
            return false; // 解析或验证过程出错
        }
    }

    /**
     * 从证书中提取SCT扩展数据
     *
     * @param string $certificate X.509证书
     *
     * @return string|false SCT扩展数据或失败返回false
     */
    protected function extractSCTFromCertificate(string $certificate)
    {
        $cert = openssl_x509_read($certificate);
        if (false === $cert) {
            return false;
        }

        $certInfo = openssl_x509_parse($cert, true);
        if (false === $certInfo || !isset($certInfo['extensions'])) {
            return false;
        }

        // 查找SCT扩展
        foreach ($certInfo['extensions'] as $oid => $value) {
            if (self::SCT_EXTENSION_OID === $oid || 'ct_precert_scts' === $oid) {
                // OpenSSL返回base64编码的值
                return base64_decode($value, true);
            }
        }

        return false;
    }

    /**
     * 提取证书的TBS部分
     *
     * @param string $certificate X.509证书
     *
     * @return string|false TBS部分或失败返回false
     */
    protected function extractTBSCertificate(string $certificate)
    {
        // 这部分实际上需要ASN.1解析，这里简化处理
        // 在实际实现中，应使用ASN.1解析库提取TBS部分

        // 模拟返回证书的TBS部分
        return hash('sha256', $certificate, true);
    }

    /**
     * 验证单个SCT
     *
     * @param array{version: int, logId: string, timestamp: int, extensions: string, signature: array{hashAlgorithm: int, signatureAlgorithm: int, signatureData: string}} $sct            单个SCT数据
     * @param string               $certificate    证书数据
     * @param string               $tbsCertificate 证书TBS部分
     *
     * @return bool 验证结果
     */
    public function validateSCT(array $sct, string $certificate, string $tbsCertificate): bool
    {
        // 获取日志公钥
        $logPublicKey = $this->fetchLogPublicKey($sct['logId']);
        if (false === $logPublicKey) {
            return false;
        }

        // 构建签名数据
        $dataToVerify = $this->constructSignedData($sct, $certificate, $tbsCertificate);

        // 验证签名
        return $this->verifySignature(
            $dataToVerify,
            $sct['signature']['signatureData'],
            $logPublicKey,
            $sct['signature']['hashAlgorithm'],
            $sct['signature']['signatureAlgorithm']
        );
    }

    /**
     * 根据日志ID获取日志公钥
     *
     * @param string $logId 日志ID
     *
     * @return string|false 日志公钥或失败返回false
     */
    protected function fetchLogPublicKey(string $logId)
    {
        // 实际应用中，应该从已知的日志服务器列表中查找
        // 这里返回一个模拟的公钥以便测试

        // 在生产环境中，应实现CT日志公钥缓存和查询

        return "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyXFr+RjALs32CvmBHSUx\n-----END PUBLIC KEY-----\n";
    }

    /**
     * 构建待验证签名的数据
     *
     * @param array{version: int, logId: string, timestamp: int, extensions: string, signature: array{hashAlgorithm: int, signatureAlgorithm: int, signatureData: string}} $sct            SCT数据
     * @param string               $certificate    证书数据
     * @param string               $tbsCertificate 证书TBS部分
     *
     * @return string 待验证的签名数据
     */
    private function constructSignedData(array $sct, string $certificate, string $tbsCertificate): string
    {
        // SCT签名数据格式: 版本 + 0x00(证书时间戳类型) + 时间戳 + 扩展 + TBS证书
        return chr($sct['version']) . chr(0x00) . $this->encodeTimestamp($sct['timestamp']) . $sct['extensions'] . $tbsCertificate;
    }

    /**
     * 编码时间戳为8字节二进制
     *
     * @param int $timestamp 时间戳
     *
     * @return string 编码后的时间戳
     */
    private function encodeTimestamp(int $timestamp): string
    {
        $result = '';
        for ($i = 7; $i >= 0; --$i) {
            $result = chr(($timestamp >> ($i * 8)) & 0xFF) . $result;
        }

        return $result;
    }

    /**
     * 验证签名
     *
     * @param string $data               待验证数据
     * @param string $signature          签名
     * @param string $publicKey          公钥
     * @param int    $hashAlgorithm      哈希算法
     * @param int    $signatureAlgorithm 签名算法
     *
     * @return bool 验证结果
     */
    protected function verifySignature(string $data, string $signature, string $publicKey, int $hashAlgorithm, int $signatureAlgorithm): bool
    {
        // 映射哈希算法
        $opensslHashAlgo = match ($hashAlgorithm) {
            self::HASH_ALGO_SHA256 => OPENSSL_ALGO_SHA256,
            self::HASH_ALGO_SHA1 => OPENSSL_ALGO_SHA1,
            default => OPENSSL_ALGO_SHA256,
        };

        // 验证签名
        $key = openssl_pkey_get_public($publicKey);
        if (false === $key) {
            return false;
        }

        // 根据签名算法选择验证方法
        if (self::SIG_ALGO_RSA === $signatureAlgorithm || self::SIG_ALGO_ECDSA === $signatureAlgorithm) {
            $result = openssl_verify($data, $signature, $key, $opensslHashAlgo);

            return 1 === $result;
        }

        return false; // 不支持的签名算法
    }
}

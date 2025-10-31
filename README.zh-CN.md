# TLS-Cert-Extensions

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-cert-extensions.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-cert-extensions)
[![PHP Version Require](https://img.shields.io/packagist/php-v/tourze/tls-cert-extensions.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-cert-extensions)
[![License](https://img.shields.io/packagist/l/tourze/tls-cert-extensions.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-cert-extensions)
[![codecov](https://codecov.io/gh/tourze/tls-cert-extensions/branch/master/graph/badge.svg?style=flat-square)](https://codecov.io/gh/tourze/tls-cert-extensions)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/tls-cert-extensions.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-cert-extensions)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-cert-extensions.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-cert-extensions)

一个用于处理 TLS 证书扩展的 PHP 库，专注于证书透明度（CT）支持和签名证书时间戳（SCT）验证。

## 功能特性

- **证书透明度（CT）支持**：解析和验证 SCT（签名证书时间戳）数据
- **SCT 验证**：验证嵌入在 X.509 证书中的 SCT 条目
- **二进制数据解析**：根据 RFC 6962 处理二进制 SCT 列表数据
- **签名验证**：使用 CT 日志公钥验证 SCT 签名
- **异常处理**：对无效 SCT 数据提供适当的错误处理

## 安装

```bash
composer require tourze/tls-cert-extensions
```

## 使用方法

### 基本 SCT 验证

```php
use Tourze\TLSCertExtensions\Certificate\SCTValidator;

$validator = new SCTValidator();

// 从二进制数据解析 SCT 列表
$scts = $validator->parseSCTList($binaryData);

// 验证包含嵌入 SCT 的证书
$certificate = file_get_contents('certificate.pem');
$isValid = $validator->validateCertificate($certificate);

if ($isValid) {
    echo "证书具有有效的 SCT";
} else {
    echo "证书具有无效或缺失的 SCT";
}
```

### 手动 SCT 验证

```php
use Tourze\TLSCertExtensions\Certificate\SCTValidator;

$validator = new SCTValidator();

// 验证单个 SCT
$sct = [
    'version' => 0,
    'logId' => $logId,
    'timestamp' => $timestamp,
    'extensions' => $extensions,
    'signature' => [
        'hashAlgorithm' => 4,        // SHA-256
        'signatureAlgorithm' => 3,   // ECDSA
        'signatureData' => $signatureData
    ]
];

$isValid = $validator->validateSCT($sct, $certificate, $tbsCertificate);
```

## 证书透明度

证书透明度（CT）是一个框架，提供开放、可审计和可验证的方式来监控 TLS 证书。此包支持：

- **SCT 解析**：从证书扩展中解析 SCT 数据
- **签名验证**：根据 CT 日志公钥验证 SCT 签名
- **二进制协议**：处理 RFC 6962 中定义的二进制 SCT 列表格式

## 异常处理

该库提供特定的异常用于错误处理：

```php
use Tourze\TLSCertExtensions\Exception\InvalidSCTDataException;

try {
    $scts = $validator->parseSCTList($data);
} catch (InvalidSCTDataException $e) {
    echo "无效的 SCT 数据: " . $e->getMessage();
}
```

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- tourze/tls-common
- tourze/tls-crypto-asymmetric
- tourze/tls-x509-core

## 贡献指南

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 获取详细信息。

## 许可证

MIT 许可证。请参阅 [License File](LICENSE) 获取更多信息。 
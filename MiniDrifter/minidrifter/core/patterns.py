# -*- coding: utf-8 -*-
"""Shared patterns and keyword dictionaries for minidrifter."""
from __future__ import annotations
import re

TEXT_EXTS = {'.js', '.json', '.wxml', '.wxss', '.html', '.wxs'}
JS_EXTS = {'.js', '.wxs'}
CONFIG_FILES = ('app.json', 'app-config.json')

EVENT_ATTR_RE = re.compile(r'\b(bind:?|catch:?|capture-bind:?|capture-catch:?)([a-zA-Z_][\w:-]*)\s*=\s*["\']([^"\']+)["\']')
DATA_ATTR_RE = re.compile(r'\bdata-([a-zA-Z0-9_-]+)\s*=\s*["\']([^"\']*)["\']')
TAG_RE = re.compile(r'<\s*([a-zA-Z0-9_-]+)([^>]*)>', re.S)
TEXT_CLEAN_RE = re.compile(r'<[^>]+>|\{\{[^}]+\}\}')

SUBJECT_KEYS = re.compile(r'(token|authorization|session|sessionid|session_key|openid|unionid|login(code)?|authcode|jwt|usertoken|markettoken|certifyidtoken)', re.I)
OBJECT_KEYS = re.compile(r'(userid|userguid|customerid|memberid|cardid|accountid|orderid|invoiceid|ticket(userid|id)?|addressid|couponid|carid|vehicleid|deviceid|houseid|billid|recordid|storeid|driverid|phoneno|phone(number)?|idcard|licen[cs]e|rescueid|targetuserid)', re.I)
CAP_KEYS = re.compile(r'(paycode|qrcode|barcode|verifycode|writeoffcode|paymenttoken|prepayid|paysign|invoiceurl|downloadurl|pickupcode|couponcode|ticketcode|certifyid|fac[e]?verify|freeze|codeurl|openorclose|unlock|lock)', re.I)
CRYPTO_KEYS = re.compile(r'(sign|signature|timestamp|timespan|nonce|random|salt|iv|key|secret|appidentity|authorization|encrypted|cipher|md5|aes|des|rsa|base64|crypt|encrypt|decrypt|hash|hmac)', re.I)
SENSITIVE_DOMAIN_KEYS = re.compile(r'(user|member|customer|balance|payment|pay|order|invoice|ticket|coupon|qrcode|verify|writeoff|device|vehicle|hicar|driver|license|idcard|rescue|account|deposit|creditcard|bank|phone|auth|login|session|door|lock|key)', re.I)

HOST_VAR_RE = re.compile(r'\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*["\'](https?://[^"\']+/?)["\']')
DIRECT_URL_RE = re.compile(r'["\'](https?://[^"\']+)["\']')

PLATFORM_APIS = {
    'wechat': {
        'request': ['wx.request'],
        'login': ['wx.login'],
        'storage_get': ['wx.getStorageSync', 'wx.getStorage'],
        'storage_set': ['wx.setStorageSync', 'wx.setStorage'],
        'navigate': ['wx.navigateTo', 'wx.redirectTo', 'wx.switchTab', 'wx.reLaunch'],
        'payment': ['wx.requestPayment'],
    },
    'alipay': {
        'request': ['my.request', 'my.httpRequest'],
        'login': ['my.getAuthCode'],
        'storage_get': ['my.getStorageSync', 'my.getStorage'],
        'storage_set': ['my.setStorageSync', 'my.setStorage'],
    },
    'baidu': {
        'request': ['swan.request'],
        'login': ['swan.login'],
    },
    'tiktok': {
        'request': ['tt.request'],
        'login': ['tt.login'],
    },
}

HTTP_METHODS = {'get', 'post', 'put', 'delete', 'patch', 'head'}

/*
 * Copyright (C) Ascensio System SIA, 2009-2026
 *
 * This program is a free software product. You can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License (AGPL)
 * version 3 as published by the Free Software Foundation, together with the
 * additional terms provided in the LICENSE file.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. For
 * details, see the GNU AGPL at: https://www.gnu.org/licenses/agpl-3.0.html
 *
 * You can contact Ascensio System SIA by email at info@onlyoffice.com
 * or by postal mail at 20A-6 Ernesta Birznieka-Upisha Street, Riga,
 * LV-1050, Latvia, European Union.
 *
 * The interactive user interfaces in modified versions of the Program
 * are required to display Appropriate Legal Notices in accordance with
 * Section 5 of the GNU AGPL version 3.
 *
 * No trademark rights are granted under this License.
 *
 * All non-code elements of the Product, including illustrations,
 * icon sets, and technical writing content, are licensed under the
 * Creative Commons Attribution-ShareAlike 4.0 International License:
 * https://creativecommons.org/licenses/by-sa/4.0/legalcode
 *
 * This license applies only to such non-code elements and does not
 * modify or replace the licensing terms applicable to the Program's
 * source code, which remains licensed under the GNU Affero General
 * Public License v3.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

'use strict';

const fs = require('node:fs');
const fsPromises = require('node:fs/promises');
const {pipeline} = require('node:stream/promises');
const express = require('express');
const ms = require('ms');
const config = require('config');
const operationContext = require('./../../../Common/sources/operationContext');
const tenantManager = require('./../../../Common/sources/tenantManager');
const utils = require('./../../../Common/sources/utils');
const storage = require('./../../../Common/sources/storage/storage-base');
const urlModule = require('url');
const path = require('path');
const mime = require('mime');
const crypto = require('crypto');

const cfgStaticContent = config.has('services.CoAuthoring.server.static_content')
  ? config.util.cloneDeep(config.get('services.CoAuthoring.server.static_content'))
  : {};
const cfgCacheStorage = config.get('storage');
const cfgPersistentStorage = operationContext.normalizePersistentStorageCfg(cfgCacheStorage, config.get('persistentStorage'));
const cfgForgottenFiles = config.get('services.CoAuthoring.server.forgottenfiles');
const cfgErrorFiles = config.get('FileConverter.converter.errorfiles');
const cfgTelemetryCustomer = process.env.DOCSERVICE_TELEMETRY_CUSTOMER ?? 'OA Docs';

const router = express.Router();

const apiJsRelativePath = 'apps/api/documents/api.js';
const telemetryCustomerRe = /([?&]customer=)(?:\{\{APP_CUSTOMER_NAME\}\}|ONLYOFFICE)/g;

function applyTelemetryCustomer(content) {
  if (!cfgTelemetryCustomer) {
    return content.replace(telemetryCustomerRe, '');
  }
  return content.replace(telemetryCustomerRe, (match, prefix) => prefix + encodeURIComponent(cfgTelemetryCustomer));
}

function createApiJsMiddleware(filePath, staticOptions) {
  let cached = {mtimeMs: -1, content: ''};
  return async (req, res) => {
    try {
      const fileStat = await fsPromises.stat(filePath);
      if (fileStat.mtimeMs !== cached.mtimeMs) {
        cached = {
          mtimeMs: fileStat.mtimeMs,
          content: applyTelemetryCustomer(await fsPromises.readFile(filePath, 'utf8'))
        };
      }
      res.set('Content-Type', mime.getType(filePath));
      const maxAge = staticOptions && staticOptions.maxAge;
      if (maxAge) {
        res.set('Cache-Control', `public, max-age=${ms(maxAge) / 1000}`);
      }
      res.send(cached.content);
    } catch (err) {
      operationContext.global.logger.error(err);
      if (!res.headersSent) {
        res.sendStatus(404);
      }
    }
  };
}

function initCacheRouter(cfgStorage, routs, configKey) {
  const {storageFolderName} = cfgStorage;

  routs.forEach(rout => {
    if (!rout) {
      return;
    }

    ['cache', 'storage-cache'].forEach(prefix => {
      const route = `/${prefix}/${storageFolderName}/${rout}`;
      router.use(route, createCacheMiddleware(prefix, cfgStorage, rout, configKey));
    });
  });
}

function createCacheMiddleware(prefix, cfgStorage, rout, configKey) {
  return async (req, res) => {
    const index = req.url.lastIndexOf('/');
    if (req.method !== 'GET' || index <= 0) {
      res.sendStatus(404);
      return;
    }

    try {
      const ctx = new operationContext.Context();
      ctx.initFromRequest(req);
      await ctx.initTenantCache();
      const tenantStorageCfg = ctx.getCfg(configKey, cfgStorage);
      // todo storageFolderName is intentionally kept the same across all tenants for simplicity
      const tenantSecret = tenantStorageCfg.fs.secretString;
      const tenantRootPath = path.join(tenantStorageCfg.fs.folderPath, rout);

      const urlParsed = urlModule.parse(req.url, true);
      const {md5, expires} = urlParsed.query;
      const numericExpires = parseInt(expires);

      if (!md5 || !numericExpires) {
        res.sendStatus(403);
        return;
      }

      const currentTime = Math.floor(Date.now() / 1000);
      if (currentTime > numericExpires) {
        res.sendStatus(410);
        return;
      }

      const uri = req.url.split('?')[0];
      const fullPath = `/${prefix}/${cfgStorage.storageFolderName}/${rout}${uri}`;
      const signatureData = numericExpires + decodeURIComponent(fullPath) + tenantSecret;

      const expectedMd5 = crypto.createHash('md5').update(signatureData).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      if (md5 !== expectedMd5) {
        res.sendStatus(403);
        return;
      }

      const filename = urlParsed.pathname && decodeURIComponent(path.basename(urlParsed.pathname));
      let filePath = decodeURI(req.url.substring(1, index));
      if (tenantStorageCfg.name === 'storage-fs') {
        const sendFileOptions = {
          root: tenantRootPath,
          dotfiles: 'deny',
          headers: {
            'Content-Disposition': 'attachment',
            ...(filename && {'Content-Type': mime.getType(filename)})
          }
        };

        res.sendFile(filePath, sendFileOptions, err => {
          if (err) {
            if (err.code === 'ERR_STREAM_PREMATURE_CLOSE' || err.code === 'ECONNRESET' || err.code === 'ECONNABORTED') {
              operationContext.global.logger.debug('client disconnected during sendFile: %s', err.stack);
            } else {
              operationContext.global.logger.error(err);
            }
            if (!res.headersSent) {
              res.status(400).end();
            }
          }
        });
      } else if (['storage-s3', 'storage-az'].includes(tenantStorageCfg.name)) {
        if (tenantManager.isMultitenantMode(ctx) && filePath.startsWith(ctx.tenant + '/')) {
          filePath = filePath.substring(ctx.tenant.length + 1);
        }
        const result = await storage.createReadStream(ctx, filePath, rout);

        res.setHeader('Content-Type', mime.getType(filename));
        res.setHeader('Content-Length', result.contentLength);
        res.setHeader('Content-Disposition', utils.getContentDisposition(filename));
        await pipeline(result.readStream, res);
      } else {
        res.sendStatus(404);
      }
    } catch (e) {
      if (e.code === 'ERR_STREAM_PREMATURE_CLOSE') {
        operationContext.global.logger.debug('client disconnected during cache streaming: %s', e.stack);
      } else {
        operationContext.global.logger.error(e);
      }
      if (!res.headersSent) {
        res.sendStatus(400);
      }
    }
  };
}

for (const i in cfgStaticContent) {
  if (Object.hasOwn(cfgStaticContent, i)) {
    const apiJsPath = path.join(cfgStaticContent[i]['path'], apiJsRelativePath);
    if (fs.existsSync(apiJsPath)) {
      router.get(path.posix.join(i, apiJsRelativePath), createApiJsMiddleware(apiJsPath, cfgStaticContent[i]['options']));
    }
    router.use(i, express.static(cfgStaticContent[i]['path'], cfgStaticContent[i]['options']));
  }
}
if (storage.needServeStatic() || tenantManager.isMultitenantMode()) {
  initCacheRouter(cfgCacheStorage, [cfgCacheStorage.cacheFolderName], 'storage');
}
if (storage.needServeStatic(cfgForgottenFiles) || tenantManager.isMultitenantMode()) {
  let persistentRouts = [cfgForgottenFiles, cfgErrorFiles];
  persistentRouts = persistentRouts.filter(rout => {
    return rout && rout.length > 0;
  });
  if (persistentRouts.length > 0) {
    initCacheRouter(cfgPersistentStorage, persistentRouts, 'persistentStorage');
  }
}

module.exports = router;

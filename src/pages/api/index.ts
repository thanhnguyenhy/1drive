import { posix as pathPosix } from 'path'

import type { NextApiRequest, NextApiResponse } from 'next'
import axios from 'axios'

import apiConfig from '../../../config/api.config'
import siteConfig from '../../../config/site.config'
import { revealObfuscatedToken } from '../../utils/oAuthHandler'
import { compareHashedToken } from '../../utils/protectedRouteHandler'
import { getOdAuthTokens, storeOdAuthTokens } from '../../utils/odAuthTokenStore'
import { runCorsMiddleware } from './raw'

const basePath = pathPosix.resolve('/', siteConfig.baseDirectory)
const clientSecret = revealObfuscatedToken(apiConfig.obfuscatedClientSecret)

export function encodePath(path: string): string {
  let encodedPath = pathPosix.join(basePath, path)
  if (encodedPath === '/' || encodedPath === '') {
    return ''
  }
  encodedPath = encodedPath.replace(/\/$/, '')
  return `:${encodeURIComponent(encodedPath)}`
}

export async function getAccessToken(): Promise<string> {
  const { accessToken, refreshToken } = await getOdAuthTokens()

  if (typeof accessToken === 'string') {
    console.log('Fetch access token from storage.')
    return accessToken
  }

  if (typeof refreshToken !== 'string') {
    console.log('No refresh token, return empty access token.')
    return ''
  }

  const body = new URLSearchParams()
  body.append('client_id', apiConfig.clientId)
  body.append('redirect_uri', apiConfig.redirectUri)
  body.append('client_secret', clientSecret)
  body.append('refresh_token', refreshToken)
  body.append('grant_type', 'refresh_token')

  const resp = await axios.post(apiConfig.authApi, body, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  })

  if ('access_token' in resp.data && 'refresh_token' in resp.data) {
    const { expires_in, access_token, refresh_token } = resp.data
    await storeOdAuthTokens({
      accessToken: access_token,
      accessTokenExpiry: parseInt(expires_in),
      refreshToken: refresh_token,
    })
    console.log('Fetch new access token with stored refresh token.')
    return access_token
  }

  return ''
}

export function getAuthTokenPath(path: string) {
  path = path.toLowerCase() + '/'
  const protectedRoutes = siteConfig.protectedRoutes as string[]
  let authTokenPath = ''
  for (let r of protectedRoutes) {
    if (typeof r !== 'string') continue
    r = r.toLowerCase().replace(/\/$/, '') + '/'
    if (path.startsWith(r)) {
      authTokenPath = `${r}.password`
      break
    }
  }
  return authTokenPath
}

export async function checkAuthRoute(
  cleanPath: string,
  accessToken: string,
  odTokenHeader: string
): Promise<{ code: 200 | 401 | 404 | 500; message: string }> {
  const authTokenPath = getAuthTokenPath(cleanPath)

  if (authTokenPath === '') {
    return { code: 200, message: '' }
  }

  try {
    const token = await axios.get(`${apiConfig.driveApi}/root${encodePath(authTokenPath)}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      params: {
        select: '@microsoft.graph.downloadUrl,file',
      },
    })

    const odProtectedToken = await axios.get(token.data['@microsoft.graph.downloadUrl'])

    if (
      !compareHashedToken({
        odTokenHeader: odTokenHeader,
        dotPassword: odProtectedToken.data.toString(),
      })
    ) {
      return { code: 401, message: 'Password required.' }
    }
  } catch (error: any) {
    if (error?.response?.status === 404) {
      return { code: 404, message: "You didn't set a password." }
    } else {
      return { code: 500, message: 'Internal server error.' }
    }
  }

  return { code: 200, message: 'Authenticated.' }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const { obfuscatedAccessToken, accessTokenExpiry, obfuscatedRefreshToken } = req.body
    const accessToken = revealObfuscatedToken(obfuscatedAccessToken)
    const refreshToken = revealObfuscatedToken(obfuscatedRefreshToken)

    if (typeof accessToken !== 'string' || typeof refreshToken !== 'string') {
      res.status(400).send('Invalid request body')
      return
    }

    await storeOdAuthTokens({ accessToken, accessTokenExpiry, refreshToken })
    res.status(200).send('OK')
    return
  }

  let { path = '/', raw = false, next = '', sort = 'lastModifiedDateTime' } = req.query

  res.setHeader('Cache-Control', 'no-store')

  if (typeof path !== 'string') {
    res.status(400).send('Path must be a string.')
    return
  }

  if (typeof raw !== 'boolean') {
    raw = raw === 'true'
  }

  if (typeof next !== 'string') {
    next = next.toString()
  }

  const accessToken = await getAccessToken()

  if (!accessToken) {
    res.status(401).send('Unauthorized.')
    return
  }

  try {
    await runCorsMiddleware(req, res)
  } catch (error) {
    res.status(500).send('Internal server error.')
    return
  }

  const cleanPath = path.replace(/\/+$/, '')

  if (cleanPath.includes('//')) {
    res.status(400).send('Invalid path.')
    return
  }

  const { code, message } = await checkAuthRoute(cleanPath, accessToken, req.headers['x-od-token'])

  if (code !== 200) {
    res.status(code).send(message)
    return
  }

  const requestUrl = `${apiConfig.driveApi}/root${encodePath(cleanPath)}`
  const isRoot = cleanPath === '/'

  const { data: folderData } = await axios.get(`${requestUrl}${isRoot ? '' : ':'}/children`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    params: {
      ...{
        select: 'name,size,id,lastModifiedDateTime,folder,file,video,image',
        $top: siteConfig.maxItems,
      },
      ...(next ? { $skipToken: next } : {}),
      ...(sort ? { $orderby: sort } : {}),
    },
  })

  let folderItems = folderData.value

  if (!raw && !isRoot) {
    const { data: parentData } = await axios.get(requestUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    folderItems = [parentData, ...folderItems]
  }

  res.status(200).send(folderItems)
}

'use strict';

const API_BASE_URL =
    '/secure-jwt-auth/api';

/* API Request */

async function apiRequest(
    endpoint,
    options = {}
) {
    const config = {
        method: options.method || 'GET',
        headers: {
            'Content-Type':
                'application/json'
        }
    };

    if (options.headers) {
        Object.assign(
            config.headers,
            options.headers
        );
    }

    if (
        Object.prototype.hasOwnProperty.call(
            options,
            'body'
        )
    ) {
        config.body = JSON.stringify(
            options.body
        );
    }

    const accessToken =
        sessionStorage.getItem(
            'access_token'
        );

    if (accessToken) {
        config.headers.Authorization =
            `Bearer ${accessToken}`;
    }

    const response =
        await fetch(
            `${API_BASE_URL}${endpoint}`,
            config
        );

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(
            'Invalid server response.'
        );
    }

    if (!response.ok) {
        const error =
            new Error(
                data.message ||
                'Request failed.'
            );

        error.status =
            response.status;

        error.data =
            data;

        throw error;
    }

    return data;
}

/* Save Tokens */

function saveTokens(data) {
    const tokenData =
        data?.data || data;

    if (tokenData?.access_token) {
        sessionStorage.setItem(
            'access_token',
            tokenData.access_token
        );
    }

    if (tokenData?.refresh_token) {
        sessionStorage.setItem(
            'refresh_token',
            tokenData.refresh_token
        );
    }
}

/* Clear Tokens */

function clearTokens() {
    sessionStorage.removeItem(
        'access_token'
    );

    sessionStorage.removeItem(
        'refresh_token'
    );
}

/* Get Access Token */

function getAccessToken() {
    return sessionStorage.getItem(
        'access_token'
    );
}

/* Get Refresh Token */

function getRefreshToken() {
    return sessionStorage.getItem(
        'refresh_token'
    );
}
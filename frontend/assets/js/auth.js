'use strict';

/* Register */

async function registerUser(
    name,
    email,
    password
) {
    return apiRequest(
        '/auth/register.php',
        {
            method: 'POST',
            body: {
                name: String(name),
                email: String(email),
                password: String(password)
            }
        }
    );
}

/* Verify Email */

async function verifyEmail(
    email,
    otp
) {
    return apiRequest(
        '/auth/verify-email.php',
        {
            method: 'POST',
            body: {
                email,
                otp
            }
        }
    );
}

/* Login */

async function loginUser(
    email,
    password
) {
    return apiRequest(
        '/auth/login.php',
        {
            method: 'POST',
            body: {
                email,
                password
            }
        }
    );
}

/* Verify Login OTP */

async function verifyLogin(
    email,
    otp
) {
    const response =
        await apiRequest(
            '/otp/verify-login.php',
            {
                method: 'POST',
                body: {
                    email,
                    otp
                }
            }
        );

    const tokenData =
        response?.data || response;

    if (
        !tokenData?.access_token ||
        !tokenData?.refresh_token
    ) {
        throw new Error(
            'Authentication tokens were not received.'
        );
    }

    saveTokens(tokenData);

    return response;
}

/* Current User */

async function getCurrentUser() {
    return apiRequest(
        '/users/me.php',
        {
            method: 'GET'
        }
    );
}

/* Logout */

async function logoutUser(
    refreshToken
) {
    if (!refreshToken) {
        clearTokens();
        return null;
    }

    try {
        return await apiRequest(
            '/auth/logout.php',
            {
                method: 'POST',
                body: {
                    refresh_token: refreshToken
                }
            }
        );
    } finally {
        clearTokens();
    }
}

/* Logout All Devices */

async function logoutAllUsers() {
    try {
        return await apiRequest(
            '/auth/logout-all.php',
            {
                method: 'POST'
            }
        );
    } finally {
        clearTokens();
    }
}
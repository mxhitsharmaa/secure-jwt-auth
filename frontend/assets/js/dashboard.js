document.addEventListener(
    'DOMContentLoaded',
    async function () {

        const userName =
            document.getElementById(
                'userName'
            );

        const userEmail =
            document.getElementById(
                'userEmail'
            );

        const message =
            document.getElementById(
                'message'
            );

        const logoutBtn =
            document.getElementById(
                'logoutBtn'
            );

        /* Check token */

        if (!getAccessToken()) {

            window.location.replace(
                'login.html'
            );

            return;
        }

        /* Load user */

        try {

            const response =
                await getCurrentUser();

            const data =
                response?.data;

            const user =
                data?.user ?? data;

            if (
                !user ||
                typeof user.name !== 'string' ||
                typeof user.email !== 'string'
            ) {
                throw new Error(
                    'Invalid profile response.'
                );
            }

            userName.textContent =
                `Welcome, ${user.name}`;

            userEmail.textContent =
                user.email;

            message.textContent =
                '';

        } catch (error) {

            clearTokens();

            window.location.replace(
                'login.html'
            );

            return;
        }

        /* Logout */

        if (logoutBtn) {

            logoutBtn.addEventListener(
                'click',
                async function () {

                    logoutBtn.disabled = true;

                    try {

                        const refreshToken =
                            getRefreshToken();

                        if (refreshToken) {

                            await logoutUser(
                                refreshToken
                            );

                        } else {

                            clearTokens();

                        }

                    } catch (error) {

                        clearTokens();

                    }

                    window.location.replace(
                        '../index.html'
                    );

                }
            );
        }

    }
);
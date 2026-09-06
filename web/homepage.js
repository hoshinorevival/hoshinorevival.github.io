const API = "http://localhost:3000";


const usernameElement =
    document.getElementById("username");

const welcomeUsername =
    document.getElementById("welcomeUsername");

const accountStatus =
    document.getElementById("accountStatus");

const apiStatus =
    document.getElementById("apiStatus");

const profileUsername =
    document.getElementById("profileUsername");

const profileID =
    document.getElementById("profileID");

const profileRole =
    document.getElementById("profileRole");

const logoutButton =
    document.getElementById("logout");


/*
 * First load the username saved during login.
 */

function loadSavedAccount() {

    const username =
        localStorage.getItem(
            "hoshino_username"
        );

    const id =
        localStorage.getItem(
            "hoshino_user_id"
        );

    const role =
        localStorage.getItem(
            "hoshino_user_role"
        );


    if (username) {

        usernameElement.textContent =
            username;

        welcomeUsername.textContent =
            ", " + username;

        profileUsername.textContent =
            username;

        profileID.textContent =
            id
                ? "#" + id
                : "Unknown";

        profileRole.textContent =
            role || "user";

        accountStatus.textContent =
            "Signed In";

    } else {

        usernameElement.textContent =
            "Guest";

        welcomeUsername.textContent =
            "";

        profileUsername.textContent =
            "Not signed in";

        profileID.textContent =
            "Not available";

        profileRole.textContent =
            "Not available";

        accountStatus.textContent =
            "Not signed in";
    }
}


/*
 * Ask the server for the real account.
 * If the server provides the username,
 * update the saved information with it.
 */

async function loadAccount() {

    try {

        const response =
            await fetch(
                API + "/api/me",
                {
                    method: "GET",
                    credentials: "include",
                    cache: "no-store"
                }
            );

        console.log(
            "Hoshino /api/me status:",
            response.status
        );


        if (!response.ok) {

            /*
             * Don't erase the locally saved username.
             * The login already told us who signed in.
             */

            return;
        }


        const data =
            await response.json();

        console.log(
            "Hoshino account:",
            data
        );


        if (
            data.loggedIn === true &&
            data.user
        ) {

            const user =
                data.user;


            if (user.username) {

                localStorage.setItem(
                    "hoshino_username",
                    user.username
                );

            }


            if (user.id !== undefined) {

                localStorage.setItem(
                    "hoshino_user_id",
                    user.id
                );

            }


            if (user.role) {

                localStorage.setItem(
                    "hoshino_user_role",
                    user.role
                );

            }


            /*
             * Update the page with the real
             * server-side account.
             */

            usernameElement.textContent =
                user.username || "User";

            welcomeUsername.textContent =
                user.username
                    ? ", " + user.username
                    : "";

            profileUsername.textContent =
                user.username || "Unknown";

            profileID.textContent =
                user.id !== undefined
                    ? "#" + user.id
                    : "Unknown";

            profileRole.textContent =
                user.role || "user";

            accountStatus.textContent =
                "Signed In";
        }

    } catch (error) {

        console.error(
            "Account connection failed:",
            error
        );

        /*
         * The saved username can still be displayed
         * even if the API temporarily can't be reached.
         */
    }
}


/*
 * Check Hoshino API.
 */

async function checkAPI() {

    try {

        const response =
            await fetch(
                API + "/api/health",
                {
                    method: "GET",
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            apiStatus.textContent =
                "Offline";

            apiStatus.classList.remove(
                "online"
            );

            return;
        }


        const data =
            await response.json();


        if (
            data.status === "online"
        ) {

            apiStatus.textContent =
                "Online";

            apiStatus.classList.add(
                "online"
            );

        } else {

            apiStatus.textContent =
                "Offline";

            apiStatus.classList.remove(
                "online"
            );
        }

    } catch (error) {

        console.error(
            "API connection failed:",
            error
        );

        apiStatus.textContent =
            "Offline";

        apiStatus.classList.remove(
            "online"
        );
    }
}


/*
 * Log out.
 */

if (logoutButton) {

    logoutButton.addEventListener(
        "click",
        async function() {

            logoutButton.disabled = true;

            logoutButton.textContent =
                "Logging out...";


            try {

                await fetch(
                    API + "/api/logout",
                    {
                        method: "POST",
                        credentials: "include"
                    }
                );

            } catch (error) {

                console.error(
                    "Logout failed:",
                    error
                );
            }


            /*
             * Remove saved account information.
             */

            localStorage.removeItem(
                "hoshino_username"
            );

            localStorage.removeItem(
                "hoshino_user_id"
            );

            localStorage.removeItem(
                "hoshino_user_role"
            );


            window.location.replace(
                "login.html"
            );
        }
    );
}


/*
 * Start everything.
 */

loadSavedAccount();
loadAccount();
checkAPI();

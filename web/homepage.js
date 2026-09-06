const API = "http://localhost:3000";


/* ================================
   GET HTML ELEMENTS
================================ */

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


/* ================================
   LOAD ACCOUNT
================================ */

async function loadAccount() {

    try {

        const response = await fetch(
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

            accountStatus.textContent =
                "Unable to check";

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

            const user = data.user;


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


    } catch (error) {

        console.error(
            "Account connection failed:",
            error
        );


        accountStatus.textContent =
            "Server unavailable";
    }
}


/* ================================
   CHECK HOSHINO API
================================ */

async function checkAPI() {

    try {

        const response = await fetch(
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


        console.log(
            "Hoshino API:",
            data
        );


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


/* ================================
   LOGOUT
================================ */

if (logoutButton) {

    logoutButton.addEventListener(
        "click",
        async function () {

            logoutButton.disabled = true;

            logoutButton.textContent =
                "Logging out...";


            try {

                const response =
                    await fetch(
                        API + "/api/logout",
                        {
                            method: "POST",
                            credentials: "include"
                        }
                    );


                console.log(
                    "Logout status:",
                    response.status
                );


            } catch (error) {

                console.error(
                    "Logout failed:",
                    error
                );
            }


            window.location.replace(
                "login.html"
            );
        }
    );
}


/* ================================
   START HOMEPAGE
================================ */

loadAccount();

checkAPI();

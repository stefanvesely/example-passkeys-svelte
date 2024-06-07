<script lang="ts">
    import Corbado from "@corbado/web-js";
    import type {SessionUser} from "@corbado/types";
    import {onMount} from "svelte";

    let user: SessionUser | undefined;
    let x:string | undefined;
    onMount(() => {
        x = Corbado.shortSession;
        
        user = Corbado.user;
        console.log(x);
    })

    async function handleLogout() {
        await Corbado.logout()
        window.location.href = "/"
    }
</script>

<div>
    {#if (user)}
        <h1>
            Profile Page
        </h1>
        <p>
            User-id: {user.sub}
        </p>
        <p>
            Name: {user.name}
        </p>
        <p>
            User-jti: {user.jti}
        </p>
        <p>
            User-iss: {user.iss}
        </p>
        <p>
            User-iss-iat: {user.iat}
        </p>
        <p>
            User-orig: {user.orig}
        </p>
        <p>
            User-exp: {user.exp}
        </p>
        <p>
            user: {x}
        </p>
        <button on:click={handleLogout}>
            Logout
        </button>
    {:else}
        <h1>
            You aren't logged in.
        </h1>
        <p>Go <a href="/">Home</a></p>
    {/if}
</div>
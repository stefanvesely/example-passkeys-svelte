<script lang="ts">
    import Corbado from '@corbado/web-js';
    import {onMount} from 'svelte';

    let authElement: HTMLDivElement;
   
    onMount(() => {
        var session =  Corbado.shortSession;
        if (session)
        {
            login();
        }
        Corbado.mountAuthUI(
            authElement, {
                onLoggedIn: () => login(),
            })
        window.location.href = "/#login-init"
    })

    function login(){
        console.log(Corbado.shortSession);
        window.location.href = "/profile"
    }

</script>
<div bind:this={authElement}></div>

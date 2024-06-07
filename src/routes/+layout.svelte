<script lang="ts">
    import Corbado from "@corbado/web-js";
    import {onMount} from "svelte";
    const PROJECT_ID = "pro-1438928754733626282";

    let isInitialized = false;
    onMount(async () => {
        await Corbado.load({
            projectId: PROJECT_ID,
            darkMode: 'on'
        });
        isInitialized = true; // Set to true once Corbado is initialized
    });
</script>

<div>
    {#if isInitialized}
        <slot></slot>
    {/if}
</div>
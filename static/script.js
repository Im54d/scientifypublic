document.querySelectorAll('.tooltip').forEach(item => {
    item.addEventListener('mouseover', event => {
        console.log(`Tooltip: ${event.target.getAttribute('data-tooltip')}`);
    });
});

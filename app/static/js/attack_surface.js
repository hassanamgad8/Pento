$(document).ready(function() {
    // Tab logic
    const assetTypeMap = {
        'domains': 'Domain',
        'ips': 'IP Address',
        'subdomains': 'Subdomain',
        'endpoints': 'Endpoint',
        'technologies': 'Technology',
        'ports': 'Port'
    };
    let globe = null;
    let globePoints = [];
    let globeObj = null;
    function hashToLatLon(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + ((hash << 5) - hash);
        }
        let lat = ((hash % 180) - 90) + Math.random();
        let lon = (((hash / 180) % 360) - 180) + Math.random();
        return { lat, lon };
    }
    function updateGlobe(assets, tab) {
        if (!globe) return;
        const allowedTabs = ['domains', 'ips', 'subdomains', 'endpoints', 'ports'];
        if (!allowedTabs.includes(tab)) {
            globe.pointsData([]);
            return;
        }
        globePoints = assets.map((a, idx) => {
            const { lat, lon } = hashToLatLon(a.value || a.id || (a.hostname || a.ip || ''));
            return {
                id: a.id,
                value: a.value,
                type: a.type,
                lat,
                lon,
                idx
            };
        });
        globe.pointsData(globePoints)
            .pointLat('lat')
            .pointLng('lon')
            .pointAltitude(0.05)
            .pointColor(() => '#0f0')
            .pointRadius(0.7)
            .onPointClick(point => {
                const tableId = '#table-' + tab;
                const $rows = $(tableId + ' tbody tr');
                $rows.removeClass('highlight-row');
                $rows.eq(point.idx).addClass('highlight-row');
                const row = $rows.get(point.idx);
                if (row) row.scrollIntoView({ behavior: 'smooth', block: 'center' });
            });
    }
    function renderAssets(assets, tab) {
        const tables = {
            'domains': '#table-domains',
            'ips': '#table-ips',
            'subdomains': '#table-subdomains',
            'endpoints': '#table-endpoints',
            'technologies': '#table-technologies',
            'ports': '#table-ports'
        };
        $(tables[tab] + ' tbody').empty();
        $('#no-assets-message').remove();
        if (!assets || assets.length === 0) {
            $(tables[tab]).after(`<div id='no-assets-message' style='color:#f00; text-align:center; margin:1rem;'>No assets found for this tab.</div>`);
            updateGlobe([], tab);
            return;
        }
        assets.forEach((a, i) => {
            let riskClass = a.risk === 'High' ? 'risk-high' : (a.risk === 'Med' ? 'risk-med' : (a.risk === 'Info' ? 'risk-info' : 'risk-low'));
            let tags = a.tags.map(tag => `<span class='tag-chip'>#${tag}</span>`).join(' ');
            let row = `<tr data-asset-idx="${i}"><td>${a.type}</td><td>${a.value}</td><td><span class='${riskClass}'>${a.risk}</span></td><td>${a.source}</td><td>${a.first_seen}</td><td>${a.last_seen}</td><td>${tags}</td><td><span class='action-icon' title='View Details'>🔍</span></td></tr>`;
            $(tables[tab] + ' tbody').append(row);
        });
        if ($.fn.DataTable.isDataTable(tables[tab])) {
            $(tables[tab]).DataTable().destroy();
        }
        $(tables[tab]).DataTable();
        $(tables[tab] + ' tbody tr').on('click', function() {
            const idx = $(this).data('asset-idx');
            $(tables[tab] + ' tbody tr').removeClass('highlight-row');
            $(this).addClass('highlight-row');
            if (globe && globePoints[idx]) {
                globe.pointOfView({ lat: globePoints[idx].lat, lng: globePoints[idx].lon, altitude: 1.5 }, 1000);
            }
        });
        updateGlobe(assets, tab);
    }
    function switchTab(tab) {
        $('.tab-btn').removeClass('active');
        $(`.tab-btn[data-tab='${tab}']`).addClass('active');
        $('.tab-table').removeClass('active');
        $('#table-' + tab).addClass('active');
        const assetType = assetTypeMap[tab];
        $.getJSON('/api/attack_surface_assets?type=' + encodeURIComponent(assetType))
            .done(function(assets) {
                renderAssets(assets, tab);
            })
            .fail(function() {
                $('#no-assets-message').remove();
                $('#table-' + tab).after(`<div id='no-assets-message' style='color:#f00; text-align:center; margin:1rem;'>Failed to load assets for this tab.</div>`);
                updateGlobe([], tab);
            });
    }
    $('.tab-btn').off('click').on('click', function() {
        const tab = $(this).data('tab');
        switchTab(tab);
    });
    // Make summary cards clickable
    $(document).on('click', '.summary-card', function() {
        const idx = $(this).index();
        const tabKeys = ['domains', 'subdomains', 'ips', 'endpoints', 'technologies', 'ports'];
        const tab = tabKeys[idx];
        switchTab(tab);
    });
    $('#asset-search').on('keyup', function() {
        let val = $(this).val().toLowerCase();
        $('.tab-table.active tbody tr').each(function() {
            let rowText = $(this).text().toLowerCase();
            $(this).toggle(rowText.indexOf(val) > -1);
        });
    });
    function renderSummary(stats) {
        const icons = [
            '🌍', '🧩', '📡', '📁', '⚙️', '⚠️'
        ];
        const labels = [
            'Domains', 'Subdomains', 'IPs', 'Endpoints', 'Technologies', 'Open Ports'
        ];
        const keys = ['domains', 'subdomains', 'ips', 'endpoints', 'technologies', 'open_ports'];
        let html = '';
        for (let i = 0; i < keys.length; i++) {
            html += `<div class=\"summary-card\"><div class=\"icon\">${icons[i]}</div><div class=\"count\">${stats[keys[i]]}</div><div class=\"label\">${labels[i]}</div></div>`;
        }
        $('#summary-panel').html(html);
    }
    $.getJSON('/api/attack_surface_stats', renderSummary);
    // Initial load: Domains tab
    switchTab('domains');
    // 3D Globe (globe.gl)
    if (window.Globe) {
        globe = Globe()(document.getElementById('globeViz'))
            .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
            .backgroundColor('#181818')
            .width(400)
            .height(400)
            .pointOfView({ lat: 20, lng: 0, altitude: 2 });
    }
    $('<style>.highlight-row { background: #0f08 !important; color: #fff !important; }</style>').appendTo('head');
}); 
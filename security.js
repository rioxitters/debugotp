(function() {
    // 🛡️ DebugOTP Advanced Security Layer
    
    // 1. Disable Context Menu
    document.addEventListener('contextmenu', e => e.preventDefault());

    // 2. Disable Keyboard Shortcuts for DevTools
    document.addEventListener('keydown', e => {
        if (
            e.key === 'F12' ||
            (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) ||
            (e.ctrlKey && e.key === 'U') ||
            (e.ctrlKey && e.key === 'S')
        ) {
            e.preventDefault();
            return false;
        }
    });

    // 3. Anti-Debugging Detection
    const detectDevTools = () => {
        const threshold = 160;
        const widthThreshold = window.outerWidth - window.innerWidth > threshold;
        const heightThreshold = window.outerHeight - window.innerHeight > threshold;
        
        if (widthThreshold || heightThreshold) {
            // DevTools might be open
            // console.clear();
        }
    };
    window.addEventListener('resize', detectDevTools);

    // 4. Debugger Trap
    setInterval(() => {
        const start = Date.now();
        (function() {
            debugger;
        }());
        const end = Date.now();
        if (end - start > 100) {
            document.body.innerHTML = `
                <div style="height:100vh; display:flex; flex-direction:column; align-items:center; justify-content:center; background:#070707; color:#c0142a; font-family:Syne,sans-serif; text-align:center; padding:20px;">
                    <div style="font-size:60px; margin-bottom:20px;">🚫</div>
                    <h1 style="font-size:24px; margin-bottom:10px;">SECURITY ALERT</h1>
                    <p style="color:rgba(255,255,255,0.6); font-size:14px; max-width:400px;">
                        Unauthorized debugging or inspection detected. This platform is fully secured to protect user data and intellectual property.
                    </p>
                    <button onclick="location.reload()" style="margin-top:20px; padding:10px 20px; background:#c0142a; border:none; border-radius:8px; color:white; cursor:pointer; font-weight:600;">Reload Page</button>
                </div>
            `;
        }
    }, 1000);

    // 5. Protect against console injection
    console.log("%c🛡️ DebugOTP Security Active", "color: #c0142a; font-size: 20px; font-weight: bold;");
    console.log("%cStop! This is a browser feature intended for developers. If someone told you to copy-paste something here, it is a scam.", "font-size: 14px;");

})();

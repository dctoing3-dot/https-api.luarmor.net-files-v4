export default function handler(req, res) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    
    // Browser detection
    if (accept.includes('text/html') && ua.includes('mozilla')) {
        res.setHeader('Content-Type', 'text/html');
        return res.status(401).send(getHTML());
    }
    
    res.status(200).json({ status: 'online', version: '4.0-VERCEL' });
}

function getHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>Unauthorized</title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body,html{width:100%;height:100%;background:#000;font-family:sans-serif;color:#fff}
        .container{height:100vh;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center}
        h1{font-size:2rem;margin-bottom:10px}
        p{color:rgba(255,255,255,0.5)}
    </style>
</head>
<body>
    <div class="container">
        <h1>⛔ Not Authorized</h1>
        <p>You are not allowed to view these files.</p>
    </div>
</body>
</html>`;
}
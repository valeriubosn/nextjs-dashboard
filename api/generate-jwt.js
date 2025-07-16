import jwt from 'jsonwebtoken';

export default function handler(req, res) {
  // Enable CORS for all origins (adjust as needed)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ 
      error: 'Method not allowed',
      message: 'Only POST requests are supported'
    });
  }

  try {
    // Get private key from environment variables
    const privateKey = process.env.JWT_PRIVATE_KEY;
    const defaultAlgorithm = process.env.JWT_ALGORITHM || 'RS256';
    
    if (!privateKey) {
      return res.status(500).json({
        error: 'Server configuration error',
        message: 'JWT_PRIVATE_KEY environment variable is not configured'
      });
    }

    const { 
      clientCode,
      payload,
      expiresIn,
      algorithm = defaultAlgorithm,
      issuer,
      audience,
      useCurrentTimestamp = true,
      customClaims = {}
    } = req.body;

    // Validate required fields
    if (!clientCode && !payload) {
      return res.status(400).json({ 
        error: 'Missing required field',
        message: 'Either clientCode or payload is required'
      });
    }

    // Build the JWT payload
    let jwtPayload;
    
    if (clientCode) {
      // API style payload with clientcode and iat (based on your original function)
      jwtPayload = {
        clientcode: clientCode,
        iat: Math.floor(Date.now() / 1000)
      };
      
      // Add custom claims if provided
      if (customClaims && typeof customClaims === 'object') {
        jwtPayload = { ...jwtPayload, ...customClaims };
      }
      
      // Add expiration if provided
      if (expiresIn) {
        const expirationTime = parseExpiresIn(expiresIn);
        jwtPayload.exp = Math.floor(Date.now() / 1000) + expirationTime;
      }
    } else {
      // Use custom payload
      jwtPayload = { ...payload };
      
      // Add iat if not present and useCurrentTimestamp is true
      if (useCurrentTimestamp && !jwtPayload.iat) {
        jwtPayload.iat = Math.floor(Date.now() / 1000);
      }
    }

    // JWT sign options
    const signOptions = {
      algorithm
    };

    // Add optional fields to sign options (not payload)
    if (issuer) signOptions.issuer = issuer;
    if (audience) signOptions.audience = audience;
    
    // Only add expiresIn to options if we're not manually setting exp in payload
    if (expiresIn && !jwtPayload.exp) {
      signOptions.expiresIn = expiresIn;
    }

    // Generate the JWT using the server-side private key
    const token = jwt.sign(jwtPayload, privateKey, signOptions);

    // Decode for verification (optional)
    const decoded = jwt.decode(token, { complete: true });

    // Return the token with metadata
    res.status(200).json({
      success: true,
      token,
      algorithm,
      payload: jwtPayload,
      header: decoded.header,
      authorizationHeader: `Bearer ${token}`,
      generatedAt: new Date().toISOString(),
      expiresIn: expiresIn || 'Not set'
    });

  } catch (error) {
    console.error('JWT Generation Error:', error);
    
    // Handle specific JWT errors
    if (error.message.includes('invalid key') || error.message.includes('PEM')) {
      return res.status(500).json({
        error: 'Invalid private key configuration',
        message: 'The server private key is invalid or malformed'
      });
    }
    
    res.status(500).json({
      error: 'JWT generation failed',
      message: error.message
    });
  }
}

// Helper function to parse expiresIn values
function parseExpiresIn(expiresIn) {
  if (typeof expiresIn === 'number') {
    return expiresIn;
  }
  
  if (typeof expiresIn === 'string') {
    const units = {
      's': 1,
      'm': 60,
      'h': 3600,
      'd': 86400,
      'w': 604800,
      'y': 31536000
    };
    
    const match = expiresIn.match(/^(\d+)([smhdwy])$/);
    if (match) {
      return parseInt(match[1]) * units[match[2]];
    }
  }
  
  return 3600; // Default to 1 hour
}

// ==== api/health.js (Health check endpoint) ====
export default function handler(req, res) {
  // Simple health check
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    privateKeyConfigured: !!process.env.JWT_PRIVATE_KEY,
    algorithm: process.env.JWT_ALGORITHM || 'RS256'
  });
}
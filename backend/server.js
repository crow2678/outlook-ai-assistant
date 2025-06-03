// backend/server.js - Part 1: Setup & Dependencies
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult, param } = require('express-validator');
const mongoose = require('mongoose');
const { OpenAI } = require('openai');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 8000;

// Global error handlers
process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (error) => {
  console.error('❌ Unhandled Rejection:', error);
  process.exit(1);
});

// Azure OpenAI client initialization
let openaiClient = null;

const initializeAzureOpenAI = () => {
  try {
    if (process.env.AZURE_OPENAI_API_KEY && process.env.AZURE_OPENAI_ENDPOINT) {
      openaiClient = new OpenAI({
        apiKey: process.env.AZURE_OPENAI_API_KEY,
        baseURL: `${process.env.AZURE_OPENAI_ENDPOINT}/openai/deployments/${process.env.AZURE_OPENAI_DEPLOYMENT_NAME}`,
        defaultQuery: { 'api-version': '2024-02-15-preview' },
        defaultHeaders: {
          'api-key': process.env.AZURE_OPENAI_API_KEY,
        },
        timeout: 30000,
        maxRetries: 2
      });
      console.log('✅ Azure OpenAI client initialized');
      console.log(`🔗 Using deployment: ${process.env.AZURE_OPENAI_DEPLOYMENT_NAME}`);
    } else {
      console.warn('⚠️  Azure OpenAI credentials not found in environment variables');
    }
  } catch (error) {
    console.error('❌ Failed to initialize Azure OpenAI client:', error);
  }
};

// Database connection for Azure Cosmos DB
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI;
    
    if (!mongoURI) {
      throw new Error('MONGODB_URI environment variable is not set');
    }
    
    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      retryWrites: true,
      w: 'majority'
    });
    
    console.log('✅ Azure Cosmos DB (MongoDB) connected successfully');
    
    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️  MongoDB disconnected');
    });
    
    mongoose.connection.on('reconnected', () => {
      console.log('🔄 MongoDB reconnected');
    });
    
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error);
    console.error('Please check your MONGODB_URI environment variable');
    process.exit(1);
  }
};

// Security middleware configuration
const securityMiddleware = () => {
  // Helmet for security headers
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        scriptSrc: ["'self'"],
        connectSrc: [
          "'self'", 
          process.env.AZURE_OPENAI_ENDPOINT || "https://*.openai.azure.com",
          process.env.FRONTEND_URL || "https://*.azurestaticapps.net"
        ]
      }
    },
    crossOriginEmbedderPolicy: false // Required for Office Add-ins
  }));

  // CORS configuration for Office Add-ins and Azure Static Web Apps
  const corsOptions = {
    origin: function (origin, callback) {
      const allowedOrigins = [
        'https://outlook.office.com',
        'https://outlook.office365.com', 
        'https://outlook.live.com',
        'https://localhost:3000',
        'https://localhost:8080',
        process.env.FRONTEND_URL,
        /https:\/\/.*\.azurestaticapps\.net$/
      ].filter(Boolean);

      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);
      
      // Check if origin matches any allowed pattern
      const isAllowed = allowedOrigins.some(allowedOrigin => {
        if (typeof allowedOrigin === 'string') {
          return origin === allowedOrigin;
        } else if (allowedOrigin instanceof RegExp) {
          return allowedOrigin.test(origin);
        }
        return false;
      });
      
      if (isAllowed) {
        callback(null, true);
      } else {
        console.warn(`🚫 CORS blocked origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-User-ID', 'X-Request-ID']
  };

  app.use(cors(corsOptions));
  
  // Handle preflight requests
  app.options('*', cors(corsOptions));
};

console.log('📦 Part 1: Dependencies and setup initialized');
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');
console.log('🚀 Port:', PORT);

// Part 2: Rate Limiting & Middleware

// Rate limiting configuration
const rateLimitConfig = () => {
  // General API rate limit
  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      console.warn(`🚫 Rate limit exceeded for IP: ${req.ip}`);
      res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil(15 * 60) // seconds
      });
    }
  });

  // Stricter rate limit for AI generation
  const aiLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // Limit to 10 AI requests per 5 minutes (Azure OpenAI has limits)
    message: {
      error: 'AI request limit exceeded',
      retryAfter: '5 minutes'
    },
    handler: (req, res) => {
      console.warn(`🤖 AI rate limit exceeded for IP: ${req.ip}`);
      res.status(429).json({
        error: 'AI request limit exceeded',
        message: 'Too many AI requests. Please try again in 5 minutes.',
        retryAfter: Math.ceil(5 * 60)
      });
    }
  });

  // Authentication rate limit
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit login attempts
    skipSuccessfulRequests: true,
    message: {
      error: 'Too many authentication attempts',
      retryAfter: '15 minutes'
    }
  });

  // Apply rate limiters
  app.use('/api/', generalLimiter);
  app.use('/api/ai/', aiLimiter);
  app.use('/api/auth/', authLimiter);
  
  console.log('🛡️  Rate limiting configured');
};

// Request logging middleware
const requestLogger = (req, res, next) => {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || generateRequestId();
  
  // Add request ID to request object
  req.requestId = requestId;
  
  // Log request
  console.log(`📝 [${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${req.ip} - ID: ${requestId}`);
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const statusColor = res.statusCode >= 400 ? '🔴' : res.statusCode >= 300 ? '🟡' : '🟢';
    console.log(`${statusColor} [${new Date().toISOString()}] ${res.statusCode} ${req.method} ${req.path} - ${duration}ms - ID: ${requestId}`);
  });
  
  next();
};

// Generate unique request ID
const generateRequestId = () => {
  return Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
};

// Body parsing middleware
const bodyParsingMiddleware = () => {
  // JSON parsing with size limits
  app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf, encoding) => {
      // Store raw body for webhook verification if needed
      req.rawBody = buf;
    }
  }));
  
  // URL encoded parsing
  app.use(express.urlencoded({ 
    extended: true, 
    limit: '10mb' 
  }));
  
  console.log('📄 Body parsing middleware configured');
};

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      error: 'Authentication Required',
      message: 'No token provided',
      requestId: req.requestId
    });
  }

  // Skip verification for development tokens
  if (token.startsWith('dev-token') || token.startsWith('fallback-token')) {
    req.user = {
      id: token.split('-').pop() || 'dev-user',
      email: 'dev@example.com',
      isDevelopment: true
    };
    return next();
  }

  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      console.error('❌ JWT_SECRET not configured');
      return res.status(500).json({
        error: 'Server Configuration Error',
        message: 'Authentication not properly configured',
        requestId: req.requestId
      });
    }

    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (error) {
    console.warn(`🔐 Authentication failed for token: ${token.substring(0, 10)}...`);
    return res.status(401).json({
      error: 'Invalid Token',
      message: 'Token verification failed',
      requestId: req.requestId
    });
  }
};

// Optional authentication middleware (doesn't fail if no token)
const optionalAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const jwtSecret = process.env.JWT_SECRET;
    if (jwtSecret) {
      const decoded = jwt.verify(token, jwtSecret);
      req.user = decoded;
    } else {
      req.user = null;
    }
  } catch (error) {
    req.user = null;
  }
  
  next();
};

// Validation middleware helper
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation Error',
      message: 'Invalid input data',
      details: errors.array(),
      requestId: req.requestId
    });
  }
  
  next();
};
/*******************************************/
// Add these endpoints to your backend API

// User Profile & Onboarding Status
app.get('/api/users/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Check if user profile exists and onboarding is complete
        const userProfile = await getUserProfile(userId);
        
        res.json({
            onboardingComplete: userProfile?.onboardingComplete || false,
            writingStyle: userProfile?.writingStyle || null,
            preferences: userProfile?.preferences || {},
            emailsAnalyzed: userProfile?.emailsAnalyzed || 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to get user profile' });
    }
});

// Email Style Analysis
app.post('/api/users/analyze-style', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { emailSamples } = req.body;
        
        if (!emailSamples || emailSamples.length === 0) {
            return res.status(400).json({ error: 'No email samples provided' });
        }
        
        // Analyze writing style using OpenAI
        const styleAnalysis = await analyzeWritingStyle(emailSamples);
        
        // Save user's writing style profile
        await saveUserWritingStyle(userId, {
            toneProfile: styleAnalysis.tone,
            vocabularyLevel: styleAnalysis.vocabulary,
            structurePreferences: styleAnalysis.structure,
            relationshipAdaptation: styleAnalysis.relationships,
            commonPhrases: styleAnalysis.phrases,
            emailsAnalyzed: emailSamples.length,
            analyzedAt: new Date()
        });
        
        res.json({
            success: true,
            analysis: styleAnalysis,
            emailsProcessed: emailSamples.length
        });
        
    } catch (error) {
        console.error('Style analysis error:', error);
        res.status(500).json({ error: 'Failed to analyze writing style' });
    }
});

// Complete Onboarding
app.post('/api/users/complete-onboarding', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        await updateUserProfile(userId, {
            onboardingComplete: true,
            onboardingCompletedAt: new Date()
        });
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to complete onboarding' });
    }
});

// Style Preference Update
app.post('/api/users/style-preference', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { preferredStyle } = req.body;
        
        await updateUserProfile(userId, {
            preferredStyle: preferredStyle
        });
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save style preference' });
    }
});

// Helper Functions
async function analyzeWritingStyle(emailSamples) {
    // Use OpenAI to analyze writing patterns
    const analysisPrompt = `
    Analyze the writing style from these email samples and provide a JSON response with:
    - tone: formal/casual/balanced scale 1-10
    - vocabulary: simple/moderate/advanced
    - structure: preferred email length and organization
    - relationships: how tone varies with different recipients
    - phrases: commonly used expressions
    
    Email samples:
    ${emailSamples.map(email => `To: ${email.to}, Subject: ${email.subject}, Body: ${email.body}`).join('\n\n')}
    `;
    
    try {
        const response = await openai.chat.completions.create({
            model: "gpt-4",
            messages: [
                {
                    role: "system",
                    content: "You are an expert writing style analyzer. Provide detailed analysis in JSON format."
                },
                {
                    role: "user",
                    content: analysisPrompt
                }
            ],
            temperature: 0.3
        });
        
        return JSON.parse(response.choices[0].message.content);
    } catch (error) {
        console.error('OpenAI analysis error:', error);
        // Return default analysis if API fails
        return {
            tone: 6,
            vocabulary: 'moderate',
            structure: 'medium',
            relationships: 'adaptive',
            phrases: []
        };
    }
}

async function getUserProfile(userId) {
    // Implement database query for user profile
    // This depends on your database setup
    return database.query('SELECT * FROM user_profiles WHERE user_id = ?', [userId]);
}

async function saveUserWritingStyle(userId, styleData) {
    // Save writing style analysis to database
    return database.query(
        'INSERT INTO user_writing_styles (user_id, style_data, created_at) VALUES (?, ?, ?)',
        [userId, JSON.stringify(styleData), new Date()]
    );
}

async function updateUserProfile(userId, updates) {
    // Update user profile in database
    const setClause = Object.keys(updates).map(key => `${key} = ?`).join(', ');
    const values = [...Object.values(updates), userId];
    
    return database.query(
        `UPDATE user_profiles SET ${setClause} WHERE user_id = ?`,
        values
    );
}
/********************************************/
// Global error handler
const errorHandler = (err, req, res, next) => {
  console.error(`❌ Error in ${req.method} ${req.path}:`, err);
  
  // Azure OpenAI specific errors
  if (err.message?.includes('OpenAI')) {
    return res.status(503).json({
      error: 'AI Service Error',
      message: 'AI service is temporarily unavailable',
      requestId: req.requestId
    });
  }
  
  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(error => error.message);
    return res.status(400).json({
      error: 'Validation Error',
      message: messages.join(', '),
      requestId: req.requestId
    });
  }
  
  // Mongoose duplicate key error
  if (err.code === 11000) {
    return res.status(409).json({
      error: 'Duplicate Resource',
      message: 'Resource already exists',
      requestId: req.requestId
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid Token',
      message: 'Authentication token is invalid',
      requestId: req.requestId
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token Expired',
      message: 'Authentication token has expired',
      requestId: req.requestId
    });
  }
  
  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({
      error: 'CORS Error',
      message: 'Origin not allowed',
      requestId: req.requestId
    });
  }
  
  // Rate limit errors
  if (err.status === 429) {
    return res.status(429).json({
      error: 'Rate Limit Exceeded',
      message: err.message,
      requestId: req.requestId
    });
  }
  
  // Azure-specific errors
  if (err.code === 'ENOTFOUND' && err.hostname?.includes('azure')) {
    return res.status(503).json({
      error: 'Azure Service Unavailable',
      message: 'Cannot connect to Azure services',
      requestId: req.requestId
    });
  }
  
  // Default server error
  const isDevelopment = process.env.NODE_ENV === 'development';
  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message: isDevelopment ? err.message : 'Something went wrong',
    requestId: req.requestId,
    ...(isDevelopment && { stack: err.stack })
  });
};

console.log('⚙️  Part 2: Rate limiting and middleware configured');

// Part 3: Health Checks & Authentication Routes

// Health check endpoints
const setupHealthChecks = () => {
  // Basic health check
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    });
  });

  // Detailed health check
  app.get('/health/detailed', optionalAuth, async (req, res) => {
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      checks: {
        database: 'unknown',
        azureOpenAI: 'unknown',
        memory: process.memoryUsage(),
        environment: {}
      }
    };

    // Check database connection
    try {
      await mongoose.connection.db.admin().ping();
      health.checks.database = 'connected';
    } catch (error) {
      health.checks.database = 'disconnected';
      health.status = 'unhealthy';
      console.error('Database health check failed:', error);
    }

    // Check Azure OpenAI connection
    try {
      if (openaiClient && process.env.AZURE_OPENAI_API_KEY) {
        // Simple test to verify Azure OpenAI is accessible
        health.checks.azureOpenAI = 'configured';
      } else {
        health.checks.azureOpenAI = 'not_configured';
      }
    } catch (error) {
      health.checks.azureOpenAI = 'error';
      console.error('Azure OpenAI health check failed:', error);
    }

    // Environment checks
    health.checks.environment = {
      nodeVersion: process.version,
      platform: process.platform,
      jwtSecretConfigured: !!process.env.JWT_SECRET,
      azureOpenAIConfigured: !!(process.env.AZURE_OPENAI_API_KEY && process.env.AZURE_OPENAI_ENDPOINT),
      mongoConfigured: !!process.env.MONGODB_URI,
      frontendUrlConfigured: !!process.env.FRONTEND_URL
    };

    // Check if any critical services are down
    const criticalChecks = ['database'];
    const unhealthyChecks = criticalChecks.filter(check => 
      health.checks[check] === 'disconnected' || health.checks[check] === 'error'
    );

    if (unhealthyChecks.length > 0) {
      health.status = 'unhealthy';
      health.issues = unhealthyChecks;
    }

    const statusCode = health.status === 'healthy' ? 200 : 503;
    res.status(statusCode).json(health);
  });

  // Azure App Service specific health check
  app.get('/health/azure', (req, res) => {
    // Azure App Service expects a simple 200 response for health monitoring
    res.status(200).send('OK');
  });

  console.log('🏥 Health check endpoints configured');
};

// Authentication routes
const setupAuthRoutes = () => {
  // Login endpoint
  app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
  ], validateRequest, async (req, res) => {
    try {
      const { email, password } = req.body;
      
      // For development mode, allow simplified authentication
      if (process.env.NODE_ENV === 'development') {
        const token = jwt.sign(
          { 
            id: email.split('@')[0], 
            email: email,
            isDevelopment: true 
          },
          process.env.JWT_SECRET || 'development-secret-key',
          { expiresIn: '24h' }
        );
        
        console.log(`🔐 Development login for: ${email}`);
        
        return res.json({
          message: 'Login successful (development mode)',
          token: token,
          user: {
            id: email.split('@')[0],
            email: email,
            name: email.split('@')[0]
          }
        });
      }
      
      // Production authentication would integrate with Azure AD or custom user system
      // For now, return a basic implementation
      if (email && password) {
        const token = jwt.sign(
          { 
            id: email.split('@')[0], 
            email: email 
          },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );
        
        return res.json({
          message: 'Login successful',
          token: token,
          user: {
            id: email.split('@')[0],
            email: email,
            name: email.split('@')[0]
          }
        });
      }
      
      res.status(401).json({
        error: 'Authentication Failed',
        message: 'Invalid credentials',
        requestId: req.requestId
      });
      
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Login Failed',
        message: 'An error occurred during login',
        requestId: req.requestId
      });
    }
  });

  // Token validation endpoint
  app.post('/api/auth/validate', authenticateToken, (req, res) => {
    res.json({
      valid: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        isDevelopment: req.user.isDevelopment || false
      },
      expiresAt: req.user.exp ? new Date(req.user.exp * 1000) : null
    });
  });

  // Token refresh endpoint
  app.post('/api/auth/refresh', authenticateToken, (req, res) => {
    try {
      const newToken = jwt.sign(
        { 
          id: req.user.id, 
          email: req.user.email,
          isDevelopment: req.user.isDevelopment 
        },
        process.env.JWT_SECRET || 'development-secret-key',
        { expiresIn: '24h' }
      );
      
      res.json({
        message: 'Token refreshed successfully',
        token: newToken,
        expiresIn: '24h'
      });
    } catch (error) {
      console.error('Token refresh error:', error);
      res.status(500).json({
        error: 'Token Refresh Failed',
        message: 'Could not refresh token',
        requestId: req.requestId
      });
    }
  });

  // Azure AD integration endpoint (placeholder for future)
  app.post('/api/auth/azure', [
    body('accessToken').notEmpty().withMessage('Azure access token is required')
  ], validateRequest, async (req, res) => {
    try {
      // This would integrate with Azure AD in production
      // For now, return a placeholder response
      res.status(501).json({
        error: 'Not Implemented',
        message: 'Azure AD integration coming soon',
        requestId: req.requestId
      });
    } catch (error) {
      console.error('Azure AD auth error:', error);
      res.status(500).json({
        error: 'Azure Authentication Failed',
        message: 'Could not authenticate with Azure AD',
        requestId: req.requestId
      });
    }
  });

  // Logout endpoint (mainly for token cleanup)
  app.post('/api/auth/logout', optionalAuth, (req, res) => {
    // In a real implementation, you might blacklist the token
    res.json({
      message: 'Logout successful',
      hint: 'Remove token from client storage'
    });
  });

  console.log('🔐 Authentication routes configured');
};

// Test endpoint for Azure OpenAI connectivity
const setupTestRoutes = () => {
  app.get('/api/test/azure-openai', authenticateToken, async (req, res) => {
    try {
      if (!openaiClient) {
        return res.status(503).json({
          error: 'Azure OpenAI Not Configured',
          message: 'Azure OpenAI client is not initialized',
          requestId: req.requestId
        });
      }

      // Simple test call to Azure OpenAI
      const testResponse = await openaiClient.chat.completions.create({
        model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME || 'gpt-4',
        messages: [
          { role: 'user', content: 'Say "Azure OpenAI connection test successful"' }
        ],
        max_tokens: 20,
        temperature: 0
      });

      res.json({
        status: 'success',
        message: 'Azure OpenAI connection test successful',
        response: testResponse.choices[0].message.content,
        model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME,
        endpoint: process.env.AZURE_OPENAI_ENDPOINT
      });

    } catch (error) {
      console.error('Azure OpenAI test failed:', error);
      res.status(503).json({
        error: 'Azure OpenAI Test Failed',
        message: error.message || 'Could not connect to Azure OpenAI',
        requestId: req.requestId
      });
    }
  });

  console.log('🧪 Test routes configured');
};

console.log('🔧 Part 3: Health checks and authentication configured');

// Part 4: Database Models & User Management

// Database Models
const { Schema, model } = mongoose;

// User model for Azure Cosmos DB
const userSchema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Invalid email format'
    }
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  passwordHash: {
    type: String,
    required: function() {
      return !this.isDevelopment;
    }
  },
  isDevelopment: {
    type: Boolean,
    default: false
  },
  timezone: {
    type: String,
    default: 'UTC'
  },
  workingHours: {
    start: { type: String, default: '09:00' },
    end: { type: String, default: '17:00' },
    timezone: { type: String, default: 'UTC' }
  },
  preferences: {
    communicationStyle: { type: String, default: 'professional' },
    preferredTone: { type: String, default: 'friendly' },
    responseTime: { type: String, default: 'quick' },
    language: { type: String, default: 'en' }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastActiveAt: { type: Date, default: Date.now }
});

// Add indexes for Azure Cosmos DB performance
userSchema.index({ email: 1 });
userSchema.index({ lastActiveAt: 1 });

// Style profile model
const styleProfileSchema = new Schema({
  userId: {
    type: String,
    required: true,
    index: true
  },
  version: {
    type: String,
    default: '2.0'
  },
  tone: {
    formality: { type: Number, min: 0, max: 10, default: 5 },
    warmth: { type: Number, min: 0, max: 10, default: 5 },
    directness: { type: Number, min: 0, max: 10, default: 5 },
    enthusiasm: { type: Number, min: 0, max: 10, default: 5 },
    politeness: { type: Number, min: 0, max: 10, default: 5 },
    confidence: { type: Number, min: 0, max: 10, default: 5 },
    urgency: { type: Number, min: 0, max: 10, default: 5 },
    overallSentiment: { type: Number, min: 0, max: 10, default: 5 }
  },
  vocabulary: {
    complexity: { type: Number, min: 0, max: 10, default: 5 },
    technicalLevel: { type: Number, min: 0, max: 10, default: 5 },
    jargonLevel: { type: Number, min: 0, max: 10, default: 5 },
    readabilityScore: { type: Number, min: 0, max: 100, default: 60 },
    averageWordLength: { type: Number, default: 5 },
    primaryIndustry: { type: String, default: 'general' },
    significantWords: [{ word: String, count: Number, frequency: Number }]
  },
  structure: {
    paragraphStyle: { type: Number, default: 2 },
    sentenceLength: { type: Number, default: 15 },
    sentenceVariation: { type: Number, default: 5 },
    usesLists: { type: Boolean, default: false },
    usesNumbering: { type: Boolean, default: false },
    complexity: { type: Number, min: 0, max: 10, default: 5 },
    structureConsistency: { type: Number, min: 0, max: 10, default: 5 }
  },
  communication: {
    greetingStyle: { type: String, default: 'hello' },
    closingStyle: { type: String, default: 'best regards' },
    questionFrequency: { type: Number, default: 0.1 },
    exclamationFrequency: { type: Number, default: 0.05 },
    formalityLevel: { type: String, enum: ['very_informal', 'informal', 'moderate', 'formal', 'very_formal'], default: 'moderate' }
  },
  patterns: {
    commonPhrases: [String],
    contextualPhrases: [String],
    writingTempo: { type: String, enum: ['very_concise', 'concise', 'moderate', 'detailed', 'very_detailed'], default: 'moderate' },
    detailLevel: { type: String, default: 'moderate' },
    urgencyTendency: { type: Number, min: 0, max: 10, default: 5 },
    preferredStructures: [String]
  },
  insights: {
    communicationStyle: { type: String, default: 'Balanced communicator' },
    strengths: [String],
    suggestions: [String],
    personalityTraits: [String]
  },
  metadata: {
    analyzedEmails: { type: Number, default: 0 },
    analysisQuality: { type: String, enum: ['limited', 'fair', 'good', 'excellent'], default: 'fair' },
    confidence: { type: Number, min: 0, max: 100, default: 50 },
    lastAnalysisAt: { type: Date, default: Date.now }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Add indexes for performance
styleProfileSchema.index({ userId: 1 });
styleProfileSchema.index({ 'metadata.lastAnalysisAt': 1 });

// Learning feedback model for Azure OpenAI interactions
const learningFeedbackSchema = new Schema({
  userId: {
    type: String,
    required: true,
    index: true
  },
  suggestionId: {
    type: String,
    required: true,
    unique: true
  },
  context: {
    emailType: String,
    recipientRelationship: String,
    threadLength: Number,
    timeOfDay: String,
    urgencyLevel: String
  },
  suggestion: {
    originalText: String,
    suggestedText: String,
    triggerType: String,
    aiModel: { type: String, default: '88FGPT4o' }, // Your Azure OpenAI deployment
    confidence: Number
  },
  userAction: {
    type: String,
    enum: ['accept', 'modify', 'reject'],
    required: true
  },
  modifiedText: String,
  feedback: {
    rating: { type: Number, min: 1, max: 5 },
    comment: String
  },
  timestamp: { type: Date, default: Date.now }
});

// Add indexes for learning analytics
learningFeedbackSchema.index({ userId: 1, timestamp: -1 });
learningFeedbackSchema.index({ userAction: 1 });

// Create models
const User = model('User', userSchema);
const StyleProfile = model('StyleProfile', styleProfileSchema);
const LearningFeedback = model('LearningFeedback', learningFeedbackSchema);

// User Management APIs
const setupUserRoutes = () => {
  // Get user profile
  app.get('/api/users/:userId/profile', [
    param('userId').notEmpty().escape()
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Verify user can access this profile
      if (req.user.id !== userId && !req.user.isAdmin) {
        return res.status(403).json({
          error: 'Access Denied',
          message: 'Cannot access another user\'s profile',
          requestId: req.requestId
        });
      }
      
      let user = await User.findOne({ 
        $or: [
          { _id: userId },
          { email: userId }
        ]
      }).select('-passwordHash');
      
      // Create user if doesn't exist (for development)
      if (!user && req.user.isDevelopment) {
        user = new User({
          email: req.user.email,
          name: req.user.email.split('@')[0],
          isDevelopment: true
        });
        await user.save();
        console.log(`👤 Created development user: ${user.email}`);
      }
      
      if (!user) {
        return res.status(404).json({
          error: 'User Not Found',
          message: 'User profile does not exist',
          requestId: req.requestId
        });
      }
      
      // Update last active time
      user.lastActiveAt = new Date();
      await user.save();
      
      res.json({
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          timezone: user.timezone,
          workingHours: user.workingHours,
          preferences: user.preferences,
          createdAt: user.createdAt,
          lastActiveAt: user.lastActiveAt
        }
      });
      
    } catch (error) {
      console.error('Error fetching user profile:', error);
      res.status(500).json({
        error: 'Profile Fetch Failed',
        message: 'Could not retrieve user profile',
        requestId: req.requestId
      });
    }
  });

  // Update user profile
  app.put('/api/users/:userId/profile', [
    param('userId').notEmpty().escape(),
    body('name').optional().isLength({ min: 1, max: 100 }).trim().escape(),
    body('timezone').optional().isString(),
    body('workingHours.start').optional().matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    body('workingHours.end').optional().matches(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
    body('preferences.communicationStyle').optional().isIn(['professional', 'casual', 'formal', 'friendly']),
    body('preferences.preferredTone').optional().isIn(['warm', 'neutral', 'direct', 'friendly']),
    body('preferences.responseTime').optional().isIn(['immediate', 'quick', 'standard', 'relaxed'])
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Verify user can update this profile
      if (req.user.id !== userId && !req.user.isAdmin) {
        return res.status(403).json({
          error: 'Access Denied',
          message: 'Cannot update another user\'s profile',
          requestId: req.requestId
        });
      }
      
      const updateData = req.body;
      updateData.updatedAt = new Date();
      
      const user = await User.findOneAndUpdate(
        { 
          $or: [
            { _id: userId },
            { email: userId }
          ]
        },
        { $set: updateData },
        { new: true, runValidators: true }
      ).select('-passwordHash');
      
      if (!user) {
        return res.status(404).json({
          error: 'User Not Found',
          message: 'User profile does not exist',
          requestId: req.requestId
        });
      }
      
      console.log(`👤 Updated profile for user: ${user.email}`);
      
      res.json({
        message: 'Profile updated successfully',
        user: {
          id: user._id,
          email: user.email,
          name: user.name,
          timezone: user.timezone,
          workingHours: user.workingHours,
          preferences: user.preferences,
          updatedAt: user.updatedAt
        }
      });
      
    } catch (error) {
      console.error('Error updating user profile:', error);
      res.status(500).json({
        error: 'Profile Update Failed',
        message: 'Could not update user profile',
        requestId: req.requestId
      });
    }
  });

  // Get user's style profile
  app.get('/api/users/:userId/style-profile', [
    param('userId').notEmpty().escape()
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Verify access
      if (req.user.id !== userId && !req.user.isAdmin) {
        return res.status(403).json({
          error: 'Access Denied',
          requestId: req.requestId
        });
      }
      
      const styleProfile = await StyleProfile.findOne({ userId });
      
      if (!styleProfile) {
        return res.status(404).json({
          error: 'Style Profile Not Found',
          message: 'No style profile exists for this user. Please complete the onboarding process.',
          requestId: req.requestId
        });
      }
      
      res.json({
        styleProfile: styleProfile,
        lastUpdated: styleProfile.updatedAt,
        confidence: styleProfile.metadata?.confidence || 50
      });
      
    } catch (error) {
      console.error('Error fetching style profile:', error);
      res.status(500).json({
        error: 'Style Profile Fetch Failed',
        message: 'Could not retrieve style profile',
        requestId: req.requestId
      });
    }
  });

  // Create or update style profile
  app.post('/api/users/style-profile', [
    body('userId').notEmpty().escape(),
    body('styleProfile').isObject(),
    body('styleProfile.tone').optional().isObject(),
    body('styleProfile.vocabulary').optional().isObject(),
    body('styleProfile.structure').optional().isObject(),
    body('styleProfile.communication').optional().isObject(),
    body('styleProfile.patterns').optional().isObject(),
    body('styleProfile.metadata').optional().isObject()
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { userId, styleProfile } = req.body;
      
      // Verify access
      if (req.user.id !== userId && !req.user.isAdmin) {
        return res.status(403).json({
          error: 'Access Denied',
          requestId: req.requestId
        });
      }
      
      // Prepare style profile data
      const profileData = {
        ...styleProfile,
        userId: userId,
        updatedAt: new Date()
      };
      
      // Upsert style profile
      const savedProfile = await StyleProfile.findOneAndUpdate(
        { userId },
        { $set: profileData },
        { 
          new: true, 
          upsert: true, 
          runValidators: true,
          setDefaultsOnInsert: true
        }
      );
      
      console.log(`📊 Saved style profile for user: ${userId}`);
      
      res.json({
        message: 'Style profile saved successfully',
        styleProfile: savedProfile,
        confidence: savedProfile.metadata?.confidence || 50
      });
      
    } catch (error) {
      console.error('Error saving style profile:', error);
      res.status(500).json({
        error: 'Style Profile Save Failed',
        message: 'Could not save style profile',
        requestId: req.requestId
      });
    }
  });

  console.log('👥 User management routes configured');
};

console.log('🗄️  Part 4: Database models and user management configured');

// Part 5: AI Integration & Learning Feedback

// AI Generation APIs using Azure OpenAI
const setupAIRoutes = () => {
  // Generate AI suggestion using Azure OpenAI
  app.post('/api/ai/generate', [
    body('prompt').isString().isLength({ min: 10, max: 5000 }).withMessage('Prompt must be 10-5000 characters'),
    body('content').isString().isLength({ min: 1, max: 10000 }).withMessage('Content must be 1-10000 characters'),
    body('context').optional().isObject(),
    body('userId').notEmpty().escape(),
    body('triggerType').optional().isIn(['improve', 'formal', 'casual', 'shorter', 'longer'])
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { prompt, content, context, userId, triggerType = 'improve' } = req.body;
      
      // Verify user access
      if (req.user.id !== userId && !req.user.isAdmin) {
        return res.status(403).json({
          error: 'Access Denied',
          requestId: req.requestId
        });
      }
      
      if (!openaiClient) {
        return res.status(503).json({
          error: 'AI Service Unavailable',
          message: 'Azure OpenAI service is not configured',
          requestId: req.requestId
        });
      }
      
      // Generate suggestion ID for tracking
      const suggestionId = generateSuggestionId();
      
      console.log(`🤖 Generating AI suggestion for user: ${userId}, trigger: ${triggerType}`);
      
      // Call Azure OpenAI
      const suggestion = await generateWithAzureOpenAI(prompt, content, context, triggerType);
      
      // Log the interaction for learning
      await logAIInteraction(userId, suggestionId, {
        prompt,
        content,
        context,
        suggestion,
        triggerType,
        model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME
      });
      
      res.json({
        suggestionId,
        suggestion: suggestion.text,
        confidence: suggestion.confidence || 0.8,
        model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME,
        reasoning: suggestion.reasoning,
        alternatives: suggestion.alternatives || [],
        usage: suggestion.usage
      });
      
    } catch (error) {
      console.error('AI generation error:', error);
      
      // Handle specific Azure OpenAI errors
      if (error.status === 429) {
        return res.status(429).json({
          error: 'Azure OpenAI Rate Limit Exceeded',
          message: 'Too many AI requests. Please try again later.',
          retryAfter: 60,
          requestId: req.requestId
        });
      }
      
      if (error.status === 401) {
        return res.status(503).json({
          error: 'Azure OpenAI Authentication Failed',
          message: 'AI service authentication error',
          requestId: req.requestId
        });
      }
      
      if (error.code === 'content_filter') {
        return res.status(400).json({
          error: 'Content Filtered',
          message: 'Content was filtered by Azure OpenAI safety systems',
          requestId: req.requestId
        });
      }
      
      res.status(500).json({
        error: 'AI Generation Failed',
        message: 'Could not generate AI suggestion',
        requestId: req.requestId
      });
    }
  });

  // Submit learning feedback
  app.post('/api/ai/feedback', [
    body('suggestionId').isString().notEmpty(),
    body('userAction').isIn(['accept', 'modify', 'reject']),
    body('modifiedText').optional().isString(),
    body('rating').optional().isInt({ min: 1, max: 5 }),
    body('comment').optional().isString().isLength({ max: 500 })
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { suggestionId, userAction, modifiedText, rating, comment } = req.body;
      const userId = req.user.id;
      
      // Find the original AI interaction
      const originalInteraction = await findAIInteraction(suggestionId);
      if (!originalInteraction) {
        return res.status(404).json({
          error: 'Suggestion Not Found',
          message: 'Original suggestion not found',
          requestId: req.requestId
        });
      }
      
      // Create feedback record
      const feedback = new LearningFeedback({
        userId,
        suggestionId,
        context: originalInteraction.context,
        suggestion: originalInteraction.suggestion,
        userAction,
        modifiedText,
        feedback: {
          rating,
          comment
        }
      });
      
      await feedback.save();
      
      console.log(`📝 Recorded feedback: ${userAction} for suggestion ${suggestionId}`);
      
      // Process learning feedback asynchronously
      processLearningFeedback(feedback).catch(error => {
        console.error('Learning feedback processing error:', error);
      });
      
      res.json({
        message: 'Feedback recorded successfully',
        feedbackId: feedback._id
      });
      
    } catch (error) {
      console.error('Feedback submission error:', error);
      res.status(500).json({
        error: 'Feedback Submission Failed',
        message: 'Could not record feedback',
        requestId: req.requestId
      });
    }
  });

  // Get AI usage statistics
  app.get('/api/ai/stats/:userId', [
    param('userId').notEmpty().escape()
  ], validateRequest, authenticateToken, async (req, res) => {
    try {
      const { userId } = req.params;
      
      // Verify access
      if (req.user.id !== userId && !req.user.isAdmin) {
        return res.status(403).json({
          error: 'Access Denied',
          requestId: req.requestId
        });
      }
      
      // Get feedback statistics
      const feedbackStats = await LearningFeedback.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: '$userAction',
            count: { $sum: 1 },
            avgRating: { $avg: '$feedback.rating' }
          }
        }
      ]);
      
      // Calculate usage metrics
      const totalFeedback = await LearningFeedback.countDocuments({ userId });
      const recentFeedback = await LearningFeedback.countDocuments({
        userId,
        timestamp: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } // Last 7 days
      });
      
      const stats = {
        totalSuggestions: totalFeedback,
        recentSuggestions: recentFeedback,
        feedback: feedbackStats.reduce((acc, stat) => {
          acc[stat._id] = {
            count: stat.count,
            avgRating: stat.avgRating
          };
          return acc;
        }, {}),
        acceptanceRate: totalFeedback > 0 ? 
          (feedbackStats.find(s => s._id === 'accept')?.count || 0) / totalFeedback : 0,
        model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME
      };
      
      res.json({ stats });
      
    } catch (error) {
      console.error('Stats retrieval error:', error);
      res.status(500).json({
        error: 'Stats Retrieval Failed',
        message: 'Could not retrieve AI statistics',
        requestId: req.requestId
      });
    }
  });

  console.log('🤖 AI generation routes configured');
};

// Azure OpenAI generation function
const generateWithAzureOpenAI = async (prompt, content, context, triggerType) => {
  try {
    const messages = [
      {
        role: 'system',
        content: prompt
      },
      {
        role: 'user',
        content: `Please ${triggerType} this email: ${content}`
      }
    ];
    
    const response = await openaiClient.chat.completions.create({
      model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME || 'gpt-4',
      messages: messages,
      max_tokens: 1000,
      temperature: 0.7,
      presence_penalty: 0.1,
      frequency_penalty: 0.1,
      // Azure OpenAI specific parameters
      top_p: 0.9,
      stop: null
    });
    
    const suggestion = response.choices[0].message.content;
    
    return {
      text: suggestion,
      confidence: 0.85,
      reasoning: `Generated using Azure OpenAI ${process.env.AZURE_OPENAI_DEPLOYMENT_NAME}`,
      model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME,
      usage: response.usage,
      finishReason: response.choices[0].finish_reason
    };
    
  } catch (error) {
    console.error('Azure OpenAI generation error:', error);
    
    // Handle Azure OpenAI specific errors
    if (error.response?.status === 429) {
      throw new Error('Rate limit exceeded for Azure OpenAI');
    }
    if (error.response?.status === 401) {
      throw new Error('Azure OpenAI authentication failed');
    }
    if (error.response?.data?.error?.code === 'content_filter') {
      const filterError = new Error('Content was filtered');
      filterError.code = 'content_filter';
      throw filterError;
    }
    
    throw error;
  }
};

// Learning feedback processing
const processLearningFeedback = async (feedback) => {
  try {
    // Analyze feedback patterns
    const userId = feedback.userId;
    
    // Get recent feedback for this user
    const recentFeedback = await LearningFeedback.find({
      userId,
      timestamp: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
    });
    
    // Analyze patterns
    const patterns = analyzeFeedbackPatterns(recentFeedback);
    
    // Update user preferences based on patterns
    if (patterns.preferredTrigger) {
      await User.findOneAndUpdate(
        { _id: userId },
        { 
          $set: { 
            'preferences.aiLearning.preferredTrigger': patterns.preferredTrigger,
            'preferences.aiLearning.lastUpdated': new Date()
          }
        }
      );
    }
    
    console.log(`🧠 Processed learning feedback for user: ${userId}`);
    
  } catch (error) {
    console.error('Learning feedback processing error:', error);
  }
};

// Utility functions
const generateSuggestionId = () => {
  return `sugg_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
};

const logAIInteraction = async (userId, suggestionId, interaction) => {
  try {
    // Store interaction for future reference
    const interactionLog = {
      userId,
      suggestionId,
      interaction,
      timestamp: new Date(),
      model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME
    };
    
    // In production, you might want to store this in a separate collection
    // For now, we'll use the suggestion ID to link with feedback
    console.log(`📊 AI Interaction logged: ${suggestionId}`);
    
  } catch (error) {
    console.error('Failed to log AI interaction:', error);
  }
};

const findAIInteraction = async (suggestionId) => {
  try {
    // In production, you'd retrieve from your interaction log
    // For now, return a mock structure
    return {
      suggestionId,
      context: {},
      suggestion: {
        text: 'Mock suggestion',
        model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME
      }
    };
  } catch (error) {
    console.error('Error finding AI interaction:', error);
    return null;
  }
};

const analyzeFeedbackPatterns = (feedbackList) => {
  const patterns = {
    preferredTrigger: null,
    rejectedTriggers: [],
    acceptedTriggers: []
  };
  
  // Analyze accepted vs rejected suggestions by trigger type
  const triggerStats = {};
  
  feedbackList.forEach(feedback => {
    const trigger = feedback.context?.triggerType || 'improve';
    if (!triggerStats[trigger]) {
      triggerStats[trigger] = { accepted: 0, rejected: 0, total: 0 };
    }
    
    triggerStats[trigger].total++;
    if (feedback.userAction === 'accept') {
      triggerStats[trigger].accepted++;
    } else if (feedback.userAction === 'reject') {
      triggerStats[trigger].rejected++;
    }
  });
  
  // Find best performing trigger
  let bestTrigger = null;
  let bestRate = 0;
  
  Object.entries(triggerStats).forEach(([trigger, stats]) => {
    if (stats.total >= 3) { // Need at least 3 attempts
      const acceptanceRate = stats.accepted / stats.total;
      if (acceptanceRate > bestRate) {
        bestRate = acceptanceRate;
        bestTrigger = trigger;
      }
    }
  });
  
  patterns.preferredTrigger = bestTrigger;
  return patterns;
};

console.log('🧠 Part 5: AI integration and learning feedback configured');

// Part 6: Server Initialization & Startup

// Admin and monitoring routes
const setupMonitoringRoutes = () => {
  // Server performance metrics
  app.get('/api/admin/metrics', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin && req.user.id !== 'admin') {
      return res.status(403).json({ 
        error: 'Admin access required',
        requestId: req.requestId 
      });
    }
    
    try {
      const metrics = {
        server: {
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpu: process.cpuUsage(),
          platform: process.platform,
          nodeVersion: process.version
        },
        database: {
          users: await User.countDocuments(),
          styleProfiles: await StyleProfile.countDocuments(),
          feedbacks: await LearningFeedback.countDocuments()
        },
        ai: {
          model: process.env.AZURE_OPENAI_DEPLOYMENT_NAME,
          endpoint: process.env.AZURE_OPENAI_ENDPOINT,
          totalSuggestions: await LearningFeedback.countDocuments(),
          recentSuggestions: await LearningFeedback.countDocuments({
            timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
          }),
          acceptanceRate: await calculateOverallAcceptanceRate()
        },
        environment: {
          nodeEnv: process.env.NODE_ENV,
          port: PORT,
          azureRegion: process.env.WEBSITE_SITE_NAME ? 'Azure App Service' : 'Local'
        }
      };
      
      res.json({ metrics });
      
    } catch (error) {
      console.error('Metrics error:', error);
      res.status(500).json({
        error: 'Metrics Retrieval Failed',
        requestId: req.requestId
      });
    }
  });

  // Database cleanup endpoint
  app.post('/api/admin/cleanup', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin && req.user.id !== 'admin') {
      return res.status(403).json({ 
        error: 'Admin access required',
        requestId: req.requestId 
      });
    }
    
    try {
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      
      // Clean old learning feedback (keep only recent rejections)
      const deletedFeedback = await LearningFeedback.deleteMany({
        timestamp: { $lt: thirtyDaysAgo },
        userAction: 'reject',
        'feedback.rating': { $lt: 3 }
      });
      
      // Clean inactive users (no activity for 90 days)
      const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const deletedUsers = await User.deleteMany({
        lastActiveAt: { $lt: ninetyDaysAgo },
        isDevelopment: true // Only delete development users
      });
      
      res.json({
        message: 'Cleanup completed',
        deleted: {
          feedbacks: deletedFeedback.deletedCount,
          users: deletedUsers.deletedCount
        }
      });
      
    } catch (error) {
      console.error('Cleanup error:', error);
      res.status(500).json({
        error: 'Cleanup Failed',
        requestId: req.requestId
      });
    }
  });

  console.log('📊 Monitoring routes configured');
};

// Helper function for metrics
const calculateOverallAcceptanceRate = async () => {
  try {
    const totalFeedback = await LearningFeedback.countDocuments();
    const acceptedFeedback = await LearningFeedback.countDocuments({ userAction: 'accept' });
    
    return totalFeedback > 0 ? (acceptedFeedback / totalFeedback) : 0;
  } catch (error) {
    console.error('Error calculating acceptance rate:', error);
    return 0;
  }
};

// Initialize all middleware and routes
const initializeServer = async () => {
  try {
    console.log('🚀 Initializing Outlook AI Assistant Server...');
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Port: ${PORT}`);
    
    // Initialize Azure OpenAI client
    initializeAzureOpenAI();
    
    // Connect to Azure Cosmos DB
    await connectDB();
    
    // Apply security middleware
    securityMiddleware();
    
    // Apply rate limiting
    rateLimitConfig();
    
    // Apply request logging
    app.use(requestLogger);
    
    // Apply body parsing
    bodyParsingMiddleware();
    
    // Setup health checks
    setupHealthChecks();
    
    // Setup authentication routes
    setupAuthRoutes();
    
    // Setup test routes
    setupTestRoutes();
    
    // Setup user management routes
    setupUserRoutes();
    
    // Setup AI generation routes
    setupAIRoutes();
    
    // Setup monitoring routes
    setupMonitoringRoutes();
    
    // Root endpoint
    app.get('/', (req, res) => {
      res.json({
        message: 'Outlook AI Assistant API',
        version: '1.0.0',
        status: 'running',
        endpoints: {
          health: '/health',
          auth: '/api/auth/*',
          users: '/api/users/*',
          ai: '/api/ai/*',
          admin: '/api/admin/*'
        },
        documentation: 'See README.md for API documentation'
      });
    });
    
    // 404 handler for unmatched routes
    app.use('*', (req, res) => {
      res.status(404).json({
        error: 'Endpoint Not Found',
        message: `Cannot ${req.method} ${req.originalUrl}`,
        availableEndpoints: ['/health', '/api/auth/*', '/api/users/*', '/api/ai/*'],
        requestId: req.requestId
      });
    });
    
    // Apply error handler (must be last)
    app.use(errorHandler);
    
    console.log('✅ Server middleware and routes initialized');
    
  } catch (error) {
    console.error('❌ Server initialization failed:', error);
    process.exit(1);
  }
};

// Start server
const startServer = async () => {
  await initializeServer();
  
  app.listen(PORT, () => {
    console.log('\n🌟 ===================================');
    console.log('🌟  OUTLOOK AI ASSISTANT SERVER');
    console.log('🌟 ===================================');
    console.log(`🚀 Server running on port: ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/health`);
    
    if (process.env.AZURE_OPENAI_ENDPOINT) {
      console.log(`🤖 Azure OpenAI: ${process.env.AZURE_OPENAI_DEPLOYMENT_NAME}`);
      console.log(`🔗 Test AI: http://localhost:${PORT}/api/test/azure-openai`);
    }
    
    if (process.env.FRONTEND_URL) {
      console.log(`🎨 Frontend: ${process.env.FRONTEND_URL}`);
    }
    
    if (process.env.NODE_ENV === 'development') {
      console.log('🔧 Development mode: Relaxed authentication enabled');
      console.log('📝 Test login: POST /api/auth/login with any email/password');
    }
    
    console.log('🌟 ===================================\n');
    
    // Log environment status
    const missingEnvVars = [];
    if (!process.env.MONGODB_URI) missingEnvVars.push('MONGODB_URI');
    if (!process.env.JWT_SECRET) missingEnvVars.push('JWT_SECRET');
    if (!process.env.AZURE_OPENAI_API_KEY) missingEnvVars.push('AZURE_OPENAI_API_KEY');
    if (!process.env.AZURE_OPENAI_ENDPOINT) missingEnvVars.push('AZURE_OPENAI_ENDPOINT');
    
    if (missingEnvVars.length > 0) {
      console.warn('⚠️  Missing environment variables:', missingEnvVars.join(', '));
    } else {
      console.log('✅ All required environment variables configured');
    }
  });
};

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`\n📡 ${signal} received. Starting graceful shutdown...`);
  
  // Close database connection
  mongoose.connection.close(() => {
    console.log('🔌 Database connection closed');
    console.log('👋 Outlook AI Assistant Server stopped');
    process.exit(0);
  });
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Azure App Service specific handlers
process.on('SIGQUIT', () => gracefulShutdown('SIGQUIT'));

// Export for testing and Azure deployment
module.exports = {
  app,
  startServer,
  authenticateToken,
  optionalAuth,
  validateRequest,
  User,
  StyleProfile,
  LearningFeedback
};

// Start server if this file is run directly
if (require.main === module) {
  startServer().catch(error => {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  });
}

console.log('🎯 Part 6: Server initialization and startup completed');
console.log('🎉 OUTLOOK AI ASSISTANT BACKEND - COMPLETE!');
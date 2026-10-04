export type Bindings = {
  DB: D1Database
  GEMINI_API_KEY?: string
  GEMINI_MODEL?: string
  RESEND_API_KEY?: string
  EMAIL_FROM?: string
  APP_BASE_URL?: string
  // "dev" logs review links to the console and echoes them in API responses
  ENVIRONMENT?: string
}

export type AuthedUser = { id: string; email: string; role: 'protected' | 'trusted' }

export type Variables = { user: AuthedUser }

export type AppEnv = { Bindings: Bindings; Variables: Variables }

export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export type ThreatAnalysis = {
  threat_level: ThreatLevel
  risk_summary: string
  user_education_message: string
  trusted_contact_alert: string
}

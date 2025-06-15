import { Controller, Post, Body, Get, Request, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto, RegisterDto, SendOtpDto, VerifyOtpDto, GoogleSsoDto } from './dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // OTP-based authentication (primary)
  @Post('send-otp')
  sendOtp(@Body() sendOtpDto: SendOtpDto) {
    this.authService.sendOtp(sendOtpDto);
  }

  @Post('verify-otp')
  verifyOtp(@Body() verifyOtpDto: VerifyOtpDto) {
    this.authService.verifyOtp(verifyOtpDto);
  }

  @Post('register')
  register(@Body() registerDto: RegisterDto) {
    this.authService.register(registerDto);
  }

  // Traditional login (fallback)
  @Post('login')
  login(@Body() loginDto: LoginDto) {
    this.authService.login(loginDto);
  }

  // SSO authentication
  @Post('google')
  googleAuth(@Body() googleSsoDto: GoogleSsoDto) {
    this.authService.googleAuth(googleSsoDto);
  }

  @Post('logout')
  logout() {
    this.authService.logout();
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Request() req) {
    this.authService.getProfile(req.user);
  }
}

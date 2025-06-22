import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../core/prisma/prisma.service';
import { LoginDto, RegisterDto, SendOtpDto, VerifyOtpDto, GoogleSsoDto } from './dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  sendOtp(sendOtpDto: SendOtpDto) {
    // TODO: Implement OTP sending logic (SMS/WhatsApp)
    console.log('Sending OTP to:', sendOtpDto.phone);
    return {
      success: true,
      message: 'OTP sent successfully',
      phone: sendOtpDto.phone,
    };
  }

  verifyOtp(verifyOtpDto: VerifyOtpDto) {
    // TODO: Implement OTP verification logic
    // On successful verification, create a JWT payload
    const payload = { username: verifyOtpDto.phone, sub: 'user-id-placeholder' }; // Replace with actual user ID
    console.log('Verifying OTP:', {
      phone: verifyOtpDto.phone,
      otp: verifyOtpDto.otp,
    });
    return {
      success: true,
      message: 'OTP verified successfully',
      access_token: this.jwtService.sign(payload),
    };
  }

  async register(registerDto: RegisterDto) {
    const { name, phone, email, password } = registerDto;

    const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

    try {
      const user = await this.prisma.user.create({
        data: {
          name,
          phone,
          email,
          password: hashedPassword,
        },
      });

      const payload = { username: user.phone, sub: user.id };
      return {
        success: true,
        message: 'Registration successful',
        access_token: this.jwtService.sign(payload),
      };
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError && error.code === 'P2002') {
        throw new ConflictException('A user with this phone or email already exists.');
      }
      throw new InternalServerErrorException('An unexpected error occurred.');
    }
  }

  async login(loginDto: LoginDto) {
    const { email, phone, password } = loginDto;

    if (!password) {
      throw new UnauthorizedException('Password is required for this login method.');
    }

    const user = await this.prisma.user.findFirst({
      where: { OR: [{ email }, { phone }] },
    });

    if (!user || !user.password) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const isPasswordMatching = await bcrypt.compare(password, user.password);

    if (!isPasswordMatching) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const payload = { username: user.phone, sub: user.id };
    return {
      success: true,
      message: 'Login successful',
      access_token: this.jwtService.sign(payload),
    };
  }

  // Google SSO
  googleAuth(googleSsoDto: GoogleSsoDto) {
    // TODO: Implement Google SSO logic
    // On successful SSO, create a JWT payload
    const payload = { username: 'google-user-email', sub: 'google-user-id' };
    console.log('Google auth with token:', googleSsoDto.idToken);
    return {
      success: true,
      message: 'Google authentication successful',
      access_token: this.jwtService.sign(payload),
    };
  }

  logout() {
    // TODO: Implement logout logic (e.g., token blocklisting)
    return {
      success: true,
      message: 'Logout successful',
    };
  }

  async getProfile(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        phone: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    return {
      success: true,
      user,
    };
  }
}

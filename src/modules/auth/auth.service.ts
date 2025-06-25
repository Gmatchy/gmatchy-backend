import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
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
    private readonly configService: ConfigService,
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
      accessToken: this.jwtService.sign(payload),
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

      const tokens = await this.getTokens(user.id, user.phone);
      await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

      return {
        success: true,
        message: 'User created successfully',
        ...tokens,
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

    const tokens = await this.getTokens(user.id, user.phone);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);

    return {
      success: true,
      message: 'Login successful',
      ...tokens,
    };
  }

  async logout(userId: string) {
    await this.prisma.user.update({
      where: { id: userId, hashedRefreshToken: { not: null } },
      data: { hashedRefreshToken: null },
    });
    return {
      success: true,
      message: 'Logout successful',
    };
  }

  async refreshToken(userId: string, refreshToken: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.hashedRefreshToken) {
      throw new ForbiddenException('Access Denied');
    }

    const isRefreshTokenMatching = await bcrypt.compare(refreshToken, user.hashedRefreshToken);

    if (!isRefreshTokenMatching) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(user.id, user.phone);
    await this.updateRefreshTokenHash(user.id, tokens.refreshToken);
    return tokens;
  }

  private async updateRefreshTokenHash(userId: string, refreshToken: string) {
    const hash = await bcrypt.hash(refreshToken, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRefreshToken: hash },
    });
  }

  private async getTokens(userId: string, username: string) {
    const payload = { sub: userId, username };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: this.configService.get<string>('JWT_EXPIRATION_TIME'),
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION_TIME'),
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  googleAuth(googleSsoDto: GoogleSsoDto) {
    // TODO: Implement Google SSO logic
    // On successful SSO, create a JWT payload
    const payload = { username: 'google-user-email', sub: 'google-user-id' };
    console.log('Google auth with token:', googleSsoDto.idToken);
    return {
      success: true,
      message: 'Google authentication successful',
      accessToken: this.jwtService.sign(payload),
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

import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { MailService } from 'src/mail/mail.service';
import * as bcrypt from 'bcrypt';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { Request } from 'express';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Injectable()
export class UserService {
  constructor(
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
    private readonly mailer: MailService,
  ) {}

  async findUser(email: string) {
    try {
      let user = await this.prisma.user.findFirst({ where: { email } });
      if (!user) {
        return 'User not found!';
      }
      return user;
    } catch (error) {
      return error;
    }
  }

  async findAll() {
    try {
      let user = this.prisma.user.findMany();
      return user;
    } catch (error) {
      return error;
    }
  }

  async findOne(id: string) {
    try {
      let user = this.prisma.user.findFirst({ where: { id } });
      return user;
    } catch (error) {
      return error;
    }
  }

  private generateOTP(length = 6): string {
    const digits = '0123456789';
    let otp = '';
    for (let i = 0; i < length; i++) {
      otp += digits[Math.floor(Math.random() * 10)];
    }
    return otp;
  }

  async register(data: CreateUserDto) {
    const existingUser = await this.prisma.user.findFirst({
      where: { email: data.email },
    });

    if (existingUser) {
      throw new BadRequestException('User already exists!');
    }

    const hash = bcrypt.hashSync(data.password, 10);
    const otp = this.generateOTP();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const newUser = await this.prisma.user.create({
      data: {
        ...data,
        password: hash,
        otp,
        otpExpiresAt,
      },
    });

    try {
      await this.mailer.sendMail(
        data.email,
        'Your OTP Code',
        `Your OTP code is: ${otp}\n\nIt will expire in 5 minutes.`,
      );
      console.log('OTP sended to: ', data.email);
    } catch (error) {
      console.log('Error to send otp: ', error);
      return error;
    }
  }

  async verifyOtp(data: VerifyOtpDto) {
    const { email, otp } = data;

    const user = await this.prisma.user.findFirst({ where: { email } });

    if (!user) throw new BadRequestException('User not found!');

    if (user.isVerified) return { message: 'User already verified' };

    if (user.otp !== otp) throw new BadRequestException('Invalid OTP!');

    if (user.otpExpiresAt && new Date() > user.otpExpiresAt) {
      throw new BadRequestException('OTP expired!');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
      },
    });

    await this.mailer.sendMail(
      data.email,
      'Registered successfully!',
      'Thank you for registering!🫱🏼‍🫲🏽✅',
    );

    return { message: 'Email verified successfully!' };
  }

  async login(data: LoginUserDto, request: Request) {
    const user = await this.prisma.user.findFirst({
      where: { email: data.email },
    });

    if (!user) {
      throw new BadRequestException('User not found!');
    }

    const match = user && (await bcrypt.compare(data.password, user.password));

    if (!match) {
      throw new BadRequestException('Wrong credentials!');
    }

    const payload = { id: user.id, role: user.role };

    const access_token = this.jwt.sign(payload, {
      secret: 'accessSecret',
      expiresIn: '15m',
    });

    const refresh_token = this.jwt.sign(payload, {
      secret: 'refreshSecret',
      expiresIn: '7d',
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await this.prisma.session.create({
      data: {
        userId: user.id,
        token: refresh_token,
        ipAddress: request.ip || '',
        expiresAt: expiresAt,
        deviceInfo: request.headers['user-agent'] || '',
      },
    });

    await this.prisma.user.update({
      where: { id: user.id },
      data: { refreshToken: refresh_token },
    });

    await this.mailer.sendMail(
      data.email,
      'Logged in',
      'You have successfully logged in ✅',
    );

    return { access_token, refresh_token };
  }

  async updatePassword(userId: string, dto: UpdatePasswordDto) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) throw new NotFoundException('User not found');

    const passwordMatches = await bcrypt.compare(
      dto.oldPassword,
      user.password,
    );
    if (!passwordMatches)
      throw new BadRequestException('Old password is incorrect');

    const hashedNewPassword = await bcrypt.hash(dto.newPassword, 10);

    await this.prisma.user.update({
      where: { id: userId },
      data: { password: hashedNewPassword },
    });

    return { message: 'Password updated successfully' };
  }

  async refreshAccessToken(data: RefreshTokenDto) {
    try {
      const payload = this.jwt.verify(data.refresh_token, {
        secret: 'refreshSecret',
      });

      const user = await this.prisma.user.findUnique({
        where: { id: payload.id },
      });

      if (!user || user.refreshToken !== data.refresh_token) {
        throw new BadRequestException('Invalid refresh token');
      }

      const newAccessToken = this.jwt.sign(
        { id: user.id, role: user.role },
        {
          secret: 'accessSecret',
          expiresIn: '15m',
        },
      );

      return {
        message: 'New access token generated successfully ✅',
        access_token: newAccessToken,
      };
    } catch (error) {
      console.error('Error refreshing access token:', error);

      throw new BadRequestException(error.message);
    }
  }

  async promoteToAdmin(req, res) {
    try {
      
    } catch (error) {
      return 
    }
  }

  async delete(id: string) {
    try {
      let remove = this.prisma.user.delete({ where: { id } });
      return remove;
    } catch (error) {
      return error;
    }
  }
}

import {
  Controller,
  Post,
  Body,
  Param,
  Get,
  Patch,
  Delete,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { Request } from 'express';
import { AuthGuard } from 'src/auth/auth.guard';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { SessionGuard } from 'src/session/session.guard';
import { RoleGuard } from 'src/role/role.guard';
import { Roles } from './decorators/roles.decorators';
import { RoleStatus } from '@prisma/client';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('register')
  async register(@Body() dto: CreateUserDto) {
    return this.userService.register(dto);
  }

  @Post('verify-otp')
  async verifyOtp(@Body() dto: VerifyOtpDto) {
    return this.userService.verifyOtp(dto);
  }

  @Post('login')
  async login(@Body() dto: LoginUserDto, @Req() req: Request) {
    return this.userService.login(dto, req);
  }

  @Post('refresh-token')
  async refreshAccessToken(@Body() dto: RefreshTokenDto) {
    return this.userService.refreshAccessToken(dto);
  }

  @Post('resend-otp')
  async resendOtp(@Body() dto: ResendOtpDto) {
    return this.userService.resendOtp(dto);
  }

  @UseGuards(AuthGuard)
  @Patch('update-password/:id')
  async updatePassword(@Req() req: Request, @Body() dto: UpdatePasswordDto) {
    return this.userService.updatePassword(req['user'], dto);
  }

  @Roles(RoleStatus.Admin)
  @UseGuards(RoleGuard)
  @UseGuards(SessionGuard)
  @UseGuards(AuthGuard)
  @Patch('update/:id')
  async update(@Param('id') id: string, @Body() dto: UpdateUserDto) {
    return this.userService.updateUser(id, dto);
  }

  @Roles(RoleStatus.Admin)
  @UseGuards(RoleGuard)
  @UseGuards(SessionGuard)
  @UseGuards(AuthGuard)
  @Get()
  async findAll() {
    return this.userService.findAll();
  }

  @Roles(RoleStatus.Admin)
  @UseGuards(RoleGuard)
  @UseGuards(SessionGuard)
  @UseGuards(AuthGuard)
  @Get(':id')
  async findOne(@Param('id') id: string) {
    return this.userService.findOne(id);
  }

  @UseGuards(AuthGuard)
  @Get('me')
  async me(@Req() req: Request) {
    return this.userService.me(req['user']);
  }

  @Roles(RoleStatus.Admin)
  @UseGuards(RoleGuard)
  @UseGuards(SessionGuard)
  @UseGuards(AuthGuard)
  @Delete(':id')
  async delete(@Param('id') id: string) {
    return this.userService.delete(id);
  }
}

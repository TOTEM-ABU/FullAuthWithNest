import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString } from 'class-validator';

export class ResendOtpDto {
  @ApiProperty({ example: 'string@gmail.com' })
  @IsString()
  @IsEmail()
  email: string;
}

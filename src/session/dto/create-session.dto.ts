import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsDateString } from 'class-validator';

export class CreateSessionDto {
  @ApiProperty()
  @IsString()
  ipAddress: string;

  @ApiProperty()
  @IsString()
  token: string;

  @ApiProperty()
  @IsString()
  userId: string;

  @ApiProperty()
  @IsDateString()
  expiresAt: string;

  @ApiProperty()
  @IsString()
  deviceInfo: string;
}

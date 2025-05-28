import { ApiProperty } from '@nestjs/swagger';
import { IsString, Length, MinLength } from 'class-validator';

export class UpdatePasswordDto {
  @IsString()
  oldPassword: string;

  @ApiProperty()
  @IsString()
  @Length(4, 8)
  newPassword: string;
}

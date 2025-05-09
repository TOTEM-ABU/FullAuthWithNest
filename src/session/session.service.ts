import { Injectable } from '@nestjs/common';
import { UpdateSessionDto } from './dto/update-session.dto';

@Injectable()
export class SessionService {
  findAll() {
    return `This action returns all session`;
  }

  remove(id: number) {
    return `This action removes a #${id} session`;
  }
}

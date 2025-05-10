import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class SessionService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll() {
    let session = await this.prisma.session.findMany();
    return session;
  }

  async remove(id: string) {
    let session = await this.prisma.session.delete({ where: { id } });
    return session;
  }
}

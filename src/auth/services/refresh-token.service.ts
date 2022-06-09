import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import { Token } from '../entities/token.entity';

@Injectable()
export class RefreshTokenService {
  constructor(@InjectRepository(Token) private readonly tokenRepository: Repository<Token>) {}

  async verify(refreshToken: string): Promise<Token> {
    // refresh token must decoded
    const token = await this.tokenRepository.findOne({ refreshToken }, { relations: ['auth'] });

    return token ? token : null;
  }

  async generate(): Promise<string> {
    return uuidv4();
  }
}

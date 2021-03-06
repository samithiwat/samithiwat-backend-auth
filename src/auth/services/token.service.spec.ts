import { faker } from '@faker-js/faker';
import { HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ServiceType } from 'src/common/enum/auth.enum';
import { CreateTokenDto } from '../dto/create-token.dto';
import { ResponseDto } from '../dto/response.dto';
import { UpdateTokenDto } from '../dto/update-token.dto';
import { Auth } from '../entities/auth.entity';
import { Token } from '../entities/token.entity';
import { TokenResponse } from '../interface/token.interface';
import { JwtService } from './jwt.service';
import { RefreshTokenService } from './refresh-token.service';
import { TokenService } from './token.service';

const MockTokenRepository = {
  save: jest.fn(),
  findOne: jest.fn(),
  softDelete: jest.fn(),
};

const MockJwtService = {
  generate: jest.fn(),
};

const MockRefreshTokenService = {
  generate: jest.fn(),
};

const MockConfigService = {
  get: jest.fn(),
};

describe('TokenService', () => {
  let tokenService: TokenService;
  let mockTokenDto: CreateTokenDto;
  let mockToken: Token;

  beforeEach(async () => {
    const tokenModule: TestingModule = await Test.createTestingModule({
      imports: [],
      providers: [
        TokenService,
        {
          provide: JwtService,
          useValue: MockJwtService,
        },
        {
          provide: RefreshTokenService,
          useValue: MockRefreshTokenService,
        },
        {
          provide: getRepositoryToken(Token),
          useValue: MockTokenRepository,
        },
        {
          provide: ConfigService,
          useValue: MockConfigService,
        },
      ],
    }).compile();

    mockTokenDto = new CreateTokenDto({
      serviceType: ServiceType.APP,
      accessToken: faker.lorem.text(),
      refreshToken: faker.lorem.text(),
      expiresDate: faker.date.soon(),
      auth: new Auth({ id: 1 }),
    });

    mockToken = new Token({
      id: 1,
      serviceType: ServiceType.APP,
      accessToken: faker.lorem.text(),
      refreshToken: faker.lorem.text(),
      expiresDate: faker.date.soon(),
    });

    tokenService = tokenModule.get<TokenService>(TokenService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(tokenService).toBeDefined();
  });

  describe('create', () => {
    it('should return token when success (app token)', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      MockTokenRepository.save.mockResolvedValue(mockToken);
      mockToken.refreshToken = faker.lorem.word();
      (want.data as Token).refreshToken = mockToken.refreshToken;
      jest.spyOn(tokenService, 'encode').mockResolvedValue(mockToken.refreshToken);

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(tokenService.encode).toBeCalledTimes(1);
    });

    it('should return token when success (third party token)', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      MockTokenRepository.save.mockResolvedValue(mockToken);
      mockToken.refreshToken = faker.lorem.word();
      mockToken.serviceType = ServiceType.GOOGLE;
      jest.spyOn(tokenService, 'encode').mockResolvedValue(mockToken.refreshToken);

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(tokenService.encode).toBeCalledTimes(0);
    });

    it('should throw error if refresh token is duplicated', async () => {
      const want: ResponseDto = new ResponseDto({
        statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: ['Refresh token already exists'],
        data: null,
      });

      MockTokenRepository.save.mockImplementation(() => {
        throw new Error('Duplicated refresh token');
      });

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(0);
    });

    it('should create new access token if dto does have provided', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      const newAccessToken = faker.lorem.word();

      (want.data as Token).accessToken = newAccessToken;

      MockJwtService.generate.mockResolvedValue(newAccessToken);
      MockTokenRepository.save.mockResolvedValue(mockToken);
      jest.spyOn(tokenService, 'encode').mockResolvedValue(mockToken.refreshToken);

      mockTokenDto.accessToken = undefined;

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(MockJwtService.generate).toBeCalledTimes(1);
    });

    it('should create new refresh token if dto does have provided', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.CREATED,
        errors: null,
        data: mockToken,
      });
      const newRefreshToken = faker.lorem.word();

      (want.data as Token).refreshToken = newRefreshToken;

      MockRefreshTokenService.generate.mockResolvedValue(newRefreshToken);
      MockTokenRepository.save.mockResolvedValue(mockToken);
      jest.spyOn(tokenService, 'encode').mockResolvedValue(mockToken.refreshToken);

      mockTokenDto.refreshToken = undefined;

      const res = await tokenService.create(mockTokenDto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.save).toBeCalledWith(mockTokenDto);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
      expect(MockRefreshTokenService.generate).toBeCalledTimes(1);
    });
  });

  describe('findOne', () => {
    it('should return the token that find with id if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      });

      MockTokenRepository.findOne.mockResolvedValue(mockToken);

      const res = await tokenService.findOne(1);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
    });

    it('should throw error if not found token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NOT_FOUND,
        errors: ['Not found token'],
        data: null,
      });

      MockTokenRepository.findOne.mockResolvedValue(undefined);

      const res = await tokenService.findOne(1);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
    });
  });

  describe('update', () => {
    it('should return token if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      });

      MockTokenRepository.save.mockResolvedValue(mockToken);
      MockTokenRepository.findOne.mockResolvedValue(want);
      jest.spyOn(tokenService, 'encode').mockResolvedValue(mockToken.refreshToken);

      const dto = new UpdateTokenDto();
      const res = await tokenService.update(1, dto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
    });

    it('should throw error if not found token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NOT_FOUND,
        errors: ['Not found token'],
        data: null,
      }) as TokenResponse;

      jest.spyOn(tokenService, 'findOne').mockResolvedValue(want);

      const dto = new UpdateTokenDto();
      const res = await tokenService.update(1, dto);

      expect(res).toStrictEqual(want);
      expect(tokenService.findOne).toBeCalledWith(1);
      expect(tokenService.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.save).toBeCalledTimes(0);
    });

    it('should throw error if refresh token is duplicated', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.UNPROCESSABLE_ENTITY,
        errors: ['Refresh token already exists'],
        data: null,
      });

      MockTokenRepository.save.mockImplementation(() => {
        throw new Error('Duplicated refresh token');
      });

      const dto = new UpdateTokenDto();
      const res = await tokenService.update(1, dto);

      expect(res).toStrictEqual(want);
      expect(MockTokenRepository.findOne).toBeCalledWith(1);
      expect(MockTokenRepository.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.save).toBeCalledTimes(1);
    });
  });

  describe('delete', () => {
    it('should return token if success', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.OK,
        errors: null,
        data: mockToken,
      }) as TokenResponse;

      jest.spyOn(tokenService, 'findOne').mockResolvedValue(want);

      const res = await tokenService.remove(1);

      expect(res).toStrictEqual(want);
      expect(tokenService.findOne).toBeCalledWith(1);
      expect(tokenService.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.softDelete).toBeCalledWith(1);
      expect(MockTokenRepository.softDelete).toBeCalledTimes(1);
    });

    it('should throw error if not found token', async () => {
      const want = new ResponseDto({
        statusCode: HttpStatus.NOT_FOUND,
        errors: ['Not found token'],
        data: null,
      }) as TokenResponse;

      jest.spyOn(tokenService, 'findOne').mockResolvedValue(want);

      const res = await tokenService.remove(1);

      expect(res).toStrictEqual(want);
      expect(tokenService.findOne).toBeCalledWith(1);
      expect(tokenService.findOne).toBeCalledTimes(1);
      expect(MockTokenRepository.softDelete).toBeCalledTimes(0);
    });
  });
});

package com.mnvsngv.hmac;

import static org.junit.Assert.*;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;

public class HMACGeneratorTest {

	private HMACGenerator generator;
	
	@Test
	public void SHA1TestWithKeylenEqualsBlocklen() throws NoSuchAlgorithmException {
		generator = new HMACGenerator("SHA-1");
		
        String key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F";
        String text = "Sample message for keylen=blocklen";
        String expectedResult = "5FD596EE78D5553C8FF4E72D266DFD192366DA29";
        
        String result = generator.byteArrayToHexString(generator.generateHMAC(text.getBytes(), generator.hexStringToByteArray(key)));
        assertTrue(result.equalsIgnoreCase(expectedResult));
	}
	
	@Test
	public void SHA1TestWithKeylenLessThanBlocklen() throws NoSuchAlgorithmException {
		generator = new HMACGenerator("SHA-1");
		
        String key = "000102030405060708090A0B0C0D0E0F10111213";
        String text = "Sample message for keylen<blocklen";
        String expectedResult = "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807";
        
        String result = generator.byteArrayToHexString(generator.generateHMAC(text.getBytes(), generator.hexStringToByteArray(key)));
        assertTrue(result.equalsIgnoreCase(expectedResult));
	}
	
	@Test
	public void SHA1TestWithKeylenMoreThanBlockLen() throws NoSuchAlgorithmException {
		generator = new HMACGenerator("SHA-1");
		
		String key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263";
		String text = "Sample message for keylen=blocklen";
		String expectedResult = "2D51B2F7750E410584662E38F133435F4C4FD42A";
		
		String result = generator.byteArrayToHexString(generator.generateHMAC(text.getBytes(), generator.hexStringToByteArray(key)));
		assertTrue(result.equalsIgnoreCase(expectedResult));
	}
	
	@Test
	public void SHA1TestWithKeylenEqualsBlocklenAndTruncatedTag() throws NoSuchAlgorithmException {
		generator = new HMACGenerator("SHA-1");
		
		String key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30";
		String text = "Sample message for keylen<blocklen, with truncated tag";
		String expectedResult = "FE3529565CD8E28C5FA79EAC";
		
		String result = generator.byteArrayToHexString(generator.generateMAC(text.getBytes(), generator.hexStringToByteArray(key), 12));
		assertTrue(result.equalsIgnoreCase(expectedResult));
	}

}

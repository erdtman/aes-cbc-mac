/* jshint esversion: 6 */
/* jslint node: true */
'use strict';
const test = require('ava');
const aesCbcMac = require('../build/index');

test('AES-MAC-128/64', async (t) => {
  const msg = Buffer.from('84634D414343A1010E4054546869732069732074686520636F6E74656E742E', 'hex');
  const key = Buffer.from('849B57219DAE48DE646D07DBB533566E', 'hex');

  const tag = await aesCbcMac.create(key, msg, 8);
  t.deepEqual(Buffer.from(tag).toString('hex').toUpperCase(), 'C1CA820E6E247089');
});

test('AES-MAC-128/128', async (t) => {
  const msg = Buffer.from('84634D414344A10118194054546869732069732074686520636F6E74656E742E', 'hex');
  const key = Buffer.from('849B57219DAE48DE646D07DBB533566E', 'hex');

  const tag = await aesCbcMac.create(key, msg, 16);
  t.is(Buffer.from(tag).toString('hex').toUpperCase(), 'B242D2A935FEB4D66FF8334AC95BF72B');
});

test('AES-MAC-256/64', async (t) => {
  const msg = Buffer.from('84634D414343A1010F4054546869732069732074686520636F6E74656E742E', 'hex');
  const key = Buffer.from('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188', 'hex');

  const tag = await aesCbcMac.create(key, msg, 8);
  t.is(Buffer.from(tag).toString('hex').toUpperCase(), '9E1226BA1F81B848');
});

test('AES-MAC-256/128', async (t) => {
  const msg = Buffer.from('84634D414344A101181A4054546869732069732074686520636F6E74656E742E', 'hex');
  const key = Buffer.from('849B57219DAE48DE646D07DBB533566E976686457C1491BE3A76DCEA6C427188', 'hex');

  const tag = await aesCbcMac.create(key, msg, 16);
  t.is(Buffer.from(tag).toString('hex').toUpperCase(), 'DB9C7598A0751C5FF3366B6205BD2AA9');
});

test('AES-MAC invalid key lenght', async (t) => {
  const msg = Buffer.from('84', 'hex');
  const key = Buffer.from('849B57219DAE48DE646D07DBB533566E97668', 'hex');
  await t.throwsAsync(() => aesCbcMac.create(key, msg, 16));
});

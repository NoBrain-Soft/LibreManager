import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, StepUpCancelledError } from '@/api/errors';
import { setStepUpHandler, withStepUp } from './stepup';

const stepupErr = () => new ApiError(403, 'stepup_required', 'step up');

afterEach(() => setStepUpHandler(null));

describe('withStepUp', () => {
  it('passes through results without prompting', async () => {
    const handler = vi.fn(() => Promise.resolve());
    setStepUpHandler(handler);
    await expect(withStepUp(() => Promise.resolve(42))).resolves.toBe(42);
    expect(handler).not.toHaveBeenCalled();
  });

  it('prompts once and retries after stepup_required', async () => {
    const handler = vi.fn(() => Promise.resolve());
    setStepUpHandler(handler);
    const fn = vi.fn().mockRejectedValueOnce(stepupErr()).mockResolvedValueOnce('ok');
    await expect(withStepUp(fn)).resolves.toBe('ok');
    expect(handler).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('does not loop when the server keeps demanding step-up', async () => {
    setStepUpHandler(() => Promise.resolve());
    const fn = vi.fn(() => Promise.reject(stepupErr()));
    await expect(withStepUp(fn)).rejects.toMatchObject({ code: 'stepup_required' });
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('propagates cancellation and other errors', async () => {
    setStepUpHandler(() => Promise.reject(new StepUpCancelledError()));
    await expect(withStepUp(() => Promise.reject(stepupErr()))).rejects.toBeInstanceOf(StepUpCancelledError);
    const forbidden = new ApiError(403, 'forbidden', 'no');
    await expect(withStepUp(() => Promise.reject(forbidden))).rejects.toBe(forbidden);
  });

  it('shares one dialog between concurrent requests', async () => {
    let resolve!: () => void;
    const handler = vi.fn(() => new Promise<void>((r) => (resolve = r)));
    setStepUpHandler(handler);
    const make = () => vi.fn().mockRejectedValueOnce(stepupErr()).mockResolvedValueOnce('done');
    const a = withStepUp(make());
    const b = withStepUp(make());
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));
    resolve();
    await expect(Promise.all([a, b])).resolves.toEqual(['done', 'done']);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('fails cleanly when no dialog is mounted', async () => {
    await expect(withStepUp(() => Promise.reject(stepupErr()))).rejects.toMatchObject({ code: 'stepup_required' });
  });
});

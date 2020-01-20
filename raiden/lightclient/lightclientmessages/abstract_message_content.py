import abc


class AbstractMessageContent(abc.ABC):
    """ Abstract representation of the different types of content that the hub returns to the light client """

    @property
    @abc.abstractmethod
    def is_signed(self):
        raise NotImplementedError

    @is_signed.setter
    @abc.abstractmethod
    def is_signed(self, val):
        raise NotImplementedError

    @abc.abstractmethod
    def to_dict(self):
        pass

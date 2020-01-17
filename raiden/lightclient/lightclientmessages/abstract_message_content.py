import abc


class AbstractMessageContent(abc.ABC):
    """ Abstract representation of the different types of content that the hub returns to the light client """
    @abc.abstractmethod
    def to_dict(self):
        pass
